package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real usque lines, 2026-09 (the Swift tests hold the same samples).
func TestClassify(t *testing.T) {
	cases := map[string]logEvent{
		"2026/09/17 00:24:56 IST HTTP proxy listening on 127.0.0.1:18080":               evListening,
		"2026/09/12 SOCKS proxy listening on 127.0.0.1:1081":                            evListening,
		"2026/09/17 00:24:58 IST Connected to MASQUE server":                            evConnected,
		"2026/09/13 Tunnel connection lost: read: operation timed out. Reconnecting...": evLost,
		"2026/09/13 Error writing to IP connection: io: read/write on closed pipe":      evError,
		"2026/09/17 00:24:56 IST Hint: l4-http-proxy is faster for TCP-only HTTP proxy": evNone,
		"2026/09/13 Failed to connect tunnel: dial tcp 162.159.198.2:443: i/o timeout":  evError,
	}
	for line, want := range cases {
		if got := classify(line); got != want {
			t.Errorf("classify(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestArgsBindLoopbackOnly(t *testing.T) {
	w := &Warp{Config: "c.json", SNI: "example.com", Port: 1080}
	a := strings.Join(w.Args(), " ")
	for _, want := range []string{"http-proxy", "-b 127.0.0.1", "-p 1080", "--always-reconnect", "-k 5s", "--http2", "-s example.com", "-d 1.1.1.1 -d 1.0.0.1"} {
		if !strings.Contains(a, want) {
			t.Errorf("args %q missing %q", a, want)
		}
	}
}

func TestWedgeDetection(t *testing.T) {
	w := &Warp{}
	w.cmd = dummyCmd()
	now := time.Now()
	if !w.noteFailure("Error writing to IP connection: io: read/write on closed pipe", now) {
		t.Fatal("closed pipe write must restart at once")
	}
	if w.noteFailure("Error writing to IP connection: closed pipe", now.Add(time.Second)) {
		t.Fatal("restart floor must stop a loop")
	}
	later := now.Add(restartFloor + time.Second)
	for i := 0; i < wedgeBurst-1; i++ {
		if w.noteFailure("Failed to dial", later.Add(time.Duration(i)*time.Second)) {
			t.Fatal("fewer than a burst must not restart")
		}
	}
	if !w.noteFailure("Failed to dial", later.Add(4*time.Second)) {
		t.Fatal("a burst of dial failures is a wedge")
	}
}

func TestRegisterRejectsBadLicense(t *testing.T) {
	if err := Register("nope", filepath.Join(t.TempDir(), "c.json"), "bad-key", ""); err == nil || !strings.Contains(err.Error(), "license key") {
		t.Fatalf("got %v", err)
	}
}

// Live: SWEEP_USQUE=<usque binary> SWEEP_WARP_CONFIG=<registered config.json>.
// Exercises the real tunnel on this machine's network, a crash of the child,
// and a stop.
func TestLiveProxyAndCrashRecovery(t *testing.T) {
	exe, cfg := os.Getenv("SWEEP_USQUE"), os.Getenv("SWEEP_WARP_CONFIG")
	if exe == "" || cfg == "" {
		t.Skip("set SWEEP_USQUE and SWEEP_WARP_CONFIG")
	}
	states := make(chan State, 32)
	w := &Warp{Exe: exe, Config: cfg, SNI: "example.com", Port: 18091, Log: testWriter{t},
		OnState: func(s State, msg string) { t.Logf("state %v %s", s, msg); states <- s }}
	w.Start()
	defer w.Stop()
	waitFor(t, states, Running)
	mustBeWarp(t, 18091)

	pid := w.cmd.Process.Pid
	w.mu.Lock()
	_ = w.cmd.Process.Kill() // an unexpected exit
	w.mu.Unlock()
	waitFor(t, states, Running)
	if w.cmd.Process.Pid == pid {
		t.Fatal("expected a new usque process")
	}
	mustBeWarp(t, 18091)

	w.Stop()
	if w.State() != Stopped {
		t.Fatalf("state after stop = %v", w.State())
	}
}

func mustBeWarp(t *testing.T, port int) {
	t.Helper()
	proxy, _ := url.Parse("http://127.0.0.1:" + itoa(port))
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	for _, u := range []string{"https://www.cloudflare.com/cdn-cgi/trace", "http://www.cloudflare.com/cdn-cgi/trace"} {
		var body []byte
		var err error
		for try := 0; try < 3; try++ {
			var resp *http.Response
			if resp, err = client.Get(u); err == nil {
				body, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
				break
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil || !strings.Contains(string(body), "warp=on") {
			t.Fatalf("%s via proxy: err=%v body=%q", u, err, body)
		}
	}
}

// Gaming mode swaps the loopback proxy for a real TUN device: a proxy only
// catches apps that read the Windows proxy setting, and games do not.
func TestGameArgsUseNativeTun(t *testing.T) {
	w := &Warp{Exe: "usque.exe", Config: "c.json", SNI: "example.com", Port: 1080, Game: true}
	args := strings.Join(w.Args(), " ")

	if !strings.Contains(args, "nativetun") {
		t.Fatalf("gaming mode must use nativetun, got: %s", args)
	}
	if strings.Contains(args, "http-proxy") || strings.Contains(args, "-p 1080") {
		t.Fatalf("gaming mode must not bind a proxy port, got: %s", args)
	}
	// IPv6 inside the tunnel re-IPs the player on every reconnect, which the
	// game server sees as a different client.
	if !strings.Contains(args, "-S") {
		t.Fatalf("gaming mode must keep IPv6 out of the tunnel, got: %s", args)
	}
	if !strings.Contains(args, "--hot-standby") {
		t.Fatalf("gaming mode must keep a warm session, got: %s", args)
	}
	// Rotation is opt-in: it stalls roughly one new connection in twenty.
	if strings.Contains(args, "--flow-ttl") {
		t.Fatalf("rotation must be off unless asked for, got: %s", args)
	}
	// nativetun has no in-process resolver and exits on an unknown flag, so
	// passing these killed usque the moment it launched and the tunnel never
	// appeared - with the failure swallowed by the background launch.
	for _, proxyOnly := range []string{"--dns-timeout", "-d 1.1.1.1"} {
		if strings.Contains(args, proxyOnly) {
			t.Fatalf("nativetun rejects %q outright, got: %s", proxyOnly, args)
		}
	}
}

func TestFlowTTLIsOptIn(t *testing.T) {
	w := &Warp{Config: "c.json", SNI: "example.com", Game: true, FlowTTL: "45s"}
	if !strings.Contains(strings.Join(w.Args(), " "), "--flow-ttl 45s") {
		t.Fatalf("flow-ttl was not passed through: %v", w.Args())
	}
	w.FlowTTL = "0"
	if strings.Contains(strings.Join(w.Args(), " "), "--flow-ttl") {
		t.Fatal(`"0" must disable rotation`)
	}
}

// Proxy mode must be untouched by any of this.
func TestProxyArgsUnchanged(t *testing.T) {
	w := &Warp{Config: "c.json", SNI: "example.com", Port: 1080}
	args := strings.Join(w.Args(), " ")
	if !strings.Contains(args, "http-proxy") || !strings.Contains(args, "-p 1080") {
		t.Fatalf("proxy mode changed: %s", args)
	}
	if strings.Contains(args, "nativetun") || strings.Contains(args, "--hot-standby") {
		t.Fatalf("proxy mode picked up gaming flags: %s", args)
	}
}

// usque announces a TUN device instead of a listener in gaming mode; without
// this the supervisor would call a healthy tunnel stalled and restart it.
func TestTunDeviceCountsAsListening(t *testing.T) {
	if classify("2026/09/18 00:40:02 Created TUN device: usque") != evListening {
		t.Fatal("TUN creation must count as the tunnel being up")
	}
}
