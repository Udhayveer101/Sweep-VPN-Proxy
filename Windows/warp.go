package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Warp runs usque (Cloudflare WARP over MASQUE) as a child process and exposes
// it as a loopback HTTP proxy. Port of Kit/Sources/SweepVPNKit/WarpController.swift:
// same flags, same log classification, same wedge restart. Windows proxy
// settings speak HTTP (Chromium reads a WinINet "socks=" entry as SOCKS4, which
// usque does not serve), so this runs `http-proxy` where the Mac runs `socks`.
type Warp struct {
	Exe, Config, SNI string
	// Game swaps the loopback proxy for a real TUN device, so traffic that
	// ignores a proxy - games, and the UDP they carry - is tunneled too.
	Game bool
	// FlowTTL retires a healthy MASQUE flow at this age so the ISP's sweep of
	// long-lived TCP flows never reaches it. Empty or "0" disables rotation;
	// it is opt-in because the swap can briefly stall new connections.
	FlowTTL string
	Port             int
	OnState          func(State, string)
	Log              io.Writer

	mu          sync.Mutex
	cmd         *exec.Cmd
	done        chan struct{}
	state       State
	stopped     bool
	failures    []time.Time
	exits       []time.Time
	lastRestart time.Time
	lastError   string

	seq     uint64 // orders state callbacks, which run off the lock
	cbMu    sync.Mutex
	applied uint64
}

type State int

const (
	Stopped State = iota
	Starting
	Running
	Failed
)

func (s State) String() string {
	return [...]string{"Off", "Starting", "Connected", "Failed"}[s]
}

var (
	wedgeWindow  = 10 * time.Second
	wedgeBurst   = 4
	restartFloor = 20 * time.Second
	stallTimeout = 30 * time.Second
	respawnDelay = 2 * time.Second
	exitWindow   = 2 * time.Minute
	exitBurst    = 5
)

// Args mirrors WarpController.arguments; the comments there record why each
// flag exists (measured on this ISP, 2026-09-12..14).
func (w *Warp) Args() []string {
	common := []string{"-s", w.SNI, "--http2", "--always-reconnect", "-k", "5s"}

	if !w.Game {
		// socks/http-proxy resolve in-process, so they take the resolver flags.
		args := append([]string{"-c", w.Config, "http-proxy"}, common...)
		args = append(args, "--dns-timeout", "15s", "-d", "1.1.1.1", "-d", "1.0.0.1")
		return append(args, "-b", "127.0.0.1", "-p", strconv.Itoa(w.Port))
	}

	// nativetun has no in-process resolver and rejects those flags outright,
	// which silently killed usque at launch. DNS is set on the interface.

	// -S keeps IPv6 out of the tunnel deliberately: with it on, every new
	// MASQUE session hands out a different public address, so a reconnect
	// changes the player's IP mid-game and the game server drops them
	// (measured 2026-09-18 - v4 held one address across every rotation).
	// --hot-standby keeps a warm session so a killed flow is replaced by a
	// promotion rather than a rebuild.
	args := append([]string{"-c", w.Config, "nativetun"}, common...)
	args = append(args, "-S", "--hot-standby")
	if w.FlowTTL != "" && w.FlowTTL != "0" {
		args = append(args, "--flow-ttl", w.FlowTTL)
	}
	return args
}

type logEvent int

const (
	evNone logEvent = iota
	evListening
	evConnected
	evLost
	evError
)

func classify(line string) logEvent {
	switch {
	case strings.Contains(line, "proxy listening on"),
		strings.Contains(line, "Created TUN device"):
		return evListening
	case strings.Contains(line, "Connected to MASQUE server"):
		return evConnected
	case strings.Contains(line, "Tunnel connection lost"):
		return evLost
	}
	l := strings.ToLower(line)
	if strings.Contains(l, "failed") || strings.Contains(l, "error") {
		return evError
	}
	return evNone
}

func (w *Warp) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// setState must be called with mu held; the callback runs on its own goroutine.
func (w *Warp) setState(s State, msg string) {
	if s == w.state && s != Failed {
		return
	}
	w.state = s
	cb := w.OnState
	if cb == nil {
		return
	}
	w.seq++
	seq := w.seq
	go func() {
		w.cbMu.Lock()
		defer w.cbMu.Unlock()
		if seq < w.applied {
			return // a newer state already went out
		}
		w.applied = seq
		cb(s, msg)
	}()
}

func (w *Warp) logf(format string, a ...any) {
	if w.Log != nil {
		fmt.Fprintf(w.Log, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", a...)
	}
}

func (w *Warp) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = false
	w.exits = nil
	if w.cmd == nil {
		w.launch()
	}
}

func (w *Warp) Stop() {
	w.mu.Lock()
	w.stopped = true
	c, done := w.cmd, w.done
	w.cmd = nil
	w.setState(Stopped, "")
	w.mu.Unlock()
	kill(c, done)
}

func kill(c *exec.Cmd, done chan struct{}) {
	if c == nil {
		return
	}
	_ = c.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// launch must be called with mu held.
func (w *Warp) launch() {
	if _, err := os.Stat(w.Config); err != nil {
		w.setState(Failed, "WARP is not set up yet. Choose \"Set up WARP…\" first.")
		return
	}
	c := exec.Command(w.Exe, w.Args()...)
	pr, pw := io.Pipe()
	c.Stdout, c.Stderr = pw, pw
	prepare(c)
	if err := c.Start(); err != nil {
		w.setState(Failed, "Could not launch WARP: "+err.Error())
		return
	}
	contain(c)
	done := make(chan struct{})
	w.cmd, w.done = c, done
	w.lastError = ""
	w.setState(Starting, "")
	w.logf("warp starting: sni=%s port=%d pid=%d", w.SNI, w.Port, c.Process.Pid)

	go func() {
		s := bufio.NewScanner(pr)
		for s.Scan() {
			w.ingest(c, s.Text())
		}
	}()
	go func() {
		time.Sleep(stallTimeout)
		w.mu.Lock()
		stalled := w.cmd == c && w.state == Starting
		w.mu.Unlock()
		if stalled {
			w.logf("warp stalled: no listener after %s", stallTimeout)
			w.restart(c, "stalled")
		}
	}()
	go func() {
		err := c.Wait()
		pw.Close()
		close(done)
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.cmd != c || w.stopped {
			return // restart() or Stop() already took over
		}
		w.cmd = nil
		now := time.Now()
		w.exits = append(prune(w.exits, now, exitWindow), now)
		w.logf("warp exited unexpectedly: %v (%s)", err, w.lastError)
		if len(w.exits) >= exitBurst {
			msg := "WARP keeps stopping"
			if w.lastError != "" {
				msg += ": " + w.lastError
			}
			w.setState(Failed, msg)
			return
		}
		// A crash is a disconnect the user did not ask for: come back.
		w.setState(Starting, "")
		time.AfterFunc(respawnDelay, func() {
			w.mu.Lock()
			defer w.mu.Unlock()
			if !w.stopped && w.cmd == nil {
				w.launch()
			}
		})
	}()
}

func prune(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) <= window {
			out = append(out, t)
		}
	}
	return out
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func (w *Warp) ingest(c *exec.Cmd, line string) {
	line = ansi.ReplaceAllString(line, "")
	w.logf("usque: %s", line)
	ev := classify(line)
	w.mu.Lock()
	if w.cmd != c {
		w.mu.Unlock()
		return
	}
	switch ev {
	case evListening:
		w.setState(Running, "")
	case evError, evLost:
		l := strings.ToLower(line)
		if ev == evLost && !strings.Contains(l, "failed") && !strings.Contains(l, "error") {
			break
		}
		w.lastError = line
		if w.noteFailure(line, time.Now()) {
			w.mu.Unlock()
			w.logf("warp restarting: tunnel wedged: %s", line)
			w.restart(c, line)
			return
		}
	}
	w.mu.Unlock()
}

// noteFailure (mu held) mirrors WarpController.noteFailure: a write onto a
// closed HTTP/2 pipe, or a burst of failures, means usque is sitting on a dead
// session it will never leave by itself.
func (w *Warp) noteFailure(line string, now time.Time) bool {
	writeFailed := strings.Contains(line, "closed pipe") ||
		strings.Contains(line, "Error writing to IP connection")
	w.failures = append(prune(w.failures, now, wedgeWindow), now)
	wedged := writeFailed || len(w.failures) >= wedgeBurst
	if !wedged || w.cmd == nil || now.Sub(w.lastRestart) < restartFloor {
		return false
	}
	w.lastRestart = now
	w.failures = nil
	return true
}

func (w *Warp) restart(c *exec.Cmd, why string) {
	w.mu.Lock()
	if w.cmd != c {
		w.mu.Unlock()
		return
	}
	done := w.done
	w.cmd = nil
	w.mu.Unlock()
	kill(c, done)
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped && w.cmd == nil {
		w.launch()
	}
}

// Register mirrors WarpRegistration.register. Only call after the user has
// accepted Cloudflare's terms: --accept-tos accepts them on their behalf.
func Register(exe, config, licenseKey, teamToken string) error {
	licenseKey = strings.TrimSpace(licenseKey)
	if licenseKey != "" && !regexp.MustCompile(`^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$`).MatchString(licenseKey) {
		return errors.New("that license key does not look right; it should look like ab12cd34-ef56gh78-ij90kl12")
	}
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(config); err != nil {
		args := []string{"-c", config, "register", "--accept-tos", "-n", "Sweep VPN"}
		if t := strings.TrimSpace(teamToken); t != "" {
			args = append(args, "--jwt", t)
		}
		if err := runOnce(exe, args, "Registration"); err != nil {
			return err
		}
		if _, err := os.Stat(config); err != nil {
			return errors.New("registration finished but no WARP configuration was saved; try again")
		}
		_ = os.Chmod(config, 0o600)
	}
	if licenseKey != "" {
		return runOnce(exe, []string{"-c", config, "account", "set", licenseKey}, "Setting the license key")
	}
	return nil
}

func runOnce(exe string, args []string, what string) error {
	c := exec.Command(exe, args...)
	prepare(c)
	out, err := c.CombinedOutput()
	if err == nil {
		return nil
	}
	reason := err.Error()
	lines := strings.Split(strings.TrimSpace(ansi.ReplaceAllString(string(out), "")), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		reason = last
	}
	return fmt.Errorf("%s failed: %s. Check your internet connection and any key you entered, then try again", what, reason)
}
