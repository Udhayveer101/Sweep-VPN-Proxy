package main

import (
	"encoding/binary"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// A datagram socketpair stands in for utun: one end is the device, the other
// is the kernel side writing framed packets and reading what we send back.
func TestUtunFraming(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, kernel := &utun{fd: fds[0]}, fds[1]

	v6 := append([]byte{0, 0, 0, unix.AF_INET6}, 0x60, 0, 0, 0)
	v4 := append([]byte{0, 0, 0, unix.AF_INET}, 0x45, 1, 2, 3)
	for _, p := range [][]byte{v6, v4} {
		if _, err := unix.Write(kernel, p); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, mtu)
	n, err := dev.ReadPacket(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := buf[:n]; string(got) != string(v4[4:]) {
		t.Fatalf("read %x, want the IPv4 packet with its header stripped (IPv6 dropped)", got)
	}

	if err := dev.WritePacket([]byte{0x45, 9, 9}); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	n, _ = unix.Read(kernel, out)
	if n != 7 || binary.BigEndian.Uint32(out) != unix.AF_INET || out[4] != 0x45 {
		t.Fatalf("wrote %x, want AF_INET header + packet", out[:n])
	}
}

// Live end-to-end check against Cloudflare, skipped unless WARP_LIVE_CONFIG
// points at a registered config.json. A userspace netstack plays the iOS
// kernel on the other end of the socketpair, so the HTTP fetch below goes
// app → "utun" framing → MASQUE over HTTP/2 → WARP → the internet.
func TestLiveFetchThroughWarp(t *testing.T) {
	path := os.Getenv("WARP_LIVE_CONFIG")
	if path == "" {
		t.Skip("set WARP_LIVE_CONFIG to a registered usque config.json")
	}
	cfg, err := load(path)
	if err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Datagrams up to the MTU plus header; the default AF_UNIX buffer is smaller.
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(cfg.IPv4)},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")}, mtu)
	if err != nil {
		t.Fatal(err)
	}
	kernel := fds[1]
	go func() { // netstack → "utun"
		bufs, sizes := [][]byte{make([]byte, 4+65535)}, []int{0}
		for {
			if _, err := dev.Read(bufs, sizes, 4); err != nil {
				return
			}
			binary.BigEndian.PutUint32(bufs[0], unix.AF_INET)
			_, _ = unix.Write(kernel, bufs[0][:4+sizes[0]])
		}
	}()
	go func() { // "utun" → netstack
		b := make([]byte, 4+65535)
		for {
			n, err := unix.Read(kernel, b)
			if err != nil {
				return
			}
			_, _ = dev.Write([][]byte{b[4:n]}, 0)
		}
	}()

	var lines []string
	var linesMu sync.Mutex
	testLog = func(s string) { linesMu.Lock(); lines = append(lines, s); linesMu.Unlock() }
	defer func() { testLog = nil }()

	if err := start(path, "example.com", fds[0]); err != nil {
		t.Fatal(err)
	}
	defer SweepWarpStop()

	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: tnet.DialContext}}
	var body []byte
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://1.1.1.1/cdn-cgi/trace")
		if err == nil {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			break
		}
		time.Sleep(time.Second)
	}
	linesMu.Lock()
	t.Logf("usque log:\n%s", strings.Join(lines, "\n"))
	linesMu.Unlock()
	if !strings.Contains(string(body), "warp=on") {
		t.Fatalf("trace did not report warp=on:\n%s", body)
	}
	t.Logf("trace:\n%s", body)
}
