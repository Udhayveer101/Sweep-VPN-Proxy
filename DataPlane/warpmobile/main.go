// Package main is the iOS WARP data plane: patched usque's MASQUE tunnel as a
// C archive, driven from the packet-tunnel extension.
//
// macOS runs usque as a child process and talks to it over a loopback SOCKS
// port. iOS allows neither a child process nor a system proxy, so the same
// tunnel code runs in-process here, reading and writing the extension's utun
// file descriptor directly (the approach WireGuard's iOS app uses). The flags
// match WarpController.arguments on macOS: HTTP/2 with a neutral SNI,
// always-reconnect, 5s HTTP/2 PINGs.
//
// Built by DataPlane/warpmobile/build.sh inside the pinned, patched usque tree.
package main

/*
#include <stdlib.h>
typedef void (*sweep_warp_log_fn)(const char *line);
static inline void sweep_warp_call_log(sweep_warp_log_fn fn, const char *line) { if (fn) fn(line); }
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.org/x/sys/unix"
)

const (
	mtu = 1280
	// Same as `-k 5s` on macOS: the path kills long-lived TCP flows every
	// 1-4 minutes and HTTP/2 PINGs are what notice it within seconds.
	keepalive      = 5 * time.Second
	reconnectDelay = time.Second
	// iOS kills a packet-tunnel extension that grows past 50 MB. Let the Go
	// GC work harder well before that instead of being jetsammed.
	memoryLimit = 32 << 20
)

var (
	mu     sync.Mutex // tunnel state and usque's global config
	cancel context.CancelFunc
	// Separate from mu: start() logs while holding mu.
	logMu sync.Mutex
	logFn C.sweep_warp_log_fn
	// testLog observes log lines in tests; C callbacks cannot be made from Go tests.
	testLog func(string)
)

func init() {
	debug.SetMemoryLimit(memoryLimit)
	log.SetFlags(0)
	log.SetOutput(logWriter{})
}

// logWriter hands every usque log line to the Swift side, which records it in
// the shared event log the app's Connection Log screen reads.
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	logMu.Lock()
	fn := logFn
	logMu.Unlock()
	for _, line := range bytes.Split(bytes.TrimRight(p, "\n"), []byte("\n")) {
		if testLog != nil {
			testLog(string(line))
		}
		cs := C.CString(string(line))
		C.sweep_warp_call_log(fn, cs)
		C.free(unsafe.Pointer(cs))
	}
	return len(p), nil
}

func cError(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

//export SweepWarpSetLogger
func SweepWarpSetLogger(fn C.sweep_warp_log_fn) {
	logMu.Lock()
	logFn = fn
	logMu.Unlock()
}

//export SweepWarpFree
func SweepWarpFree(p *C.char) { C.free(unsafe.Pointer(p)) }

// SweepWarpRegister creates a free, anonymous WARP device and writes its keys
// to configPath, exactly what `usque register --accept-tos` does. Only call it
// after the user accepted Cloudflare's terms. Returns NULL or an error string
// the caller frees with SweepWarpFree.
//
//export SweepWarpRegister
func SweepWarpRegister(configPath, deviceName, teamToken *C.char) *C.char {
	return cError(register(C.GoString(configPath), C.GoString(deviceName), C.GoString(teamToken)))
}

func register(path, name, jwt string) error {
	account, err := api.Register(internal.DefaultModel, internal.DefaultLocale, jwt, true)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	priv, pub, err := internal.GenerateEcKeyPair()
	if err != nil {
		return fmt.Errorf("could not generate a device key: %w", err)
	}
	updated, err := api.EnrollKey(account.ID, account.Token, pub, name)
	if err != nil {
		return fmt.Errorf("enrolling the device key failed: %w", err)
	}
	if len(updated.Config.Peers) == 0 {
		return errors.New("Cloudflare returned no WARP endpoint")
	}
	peer := updated.Config.Peers[0]
	v4, v6 := peer.Endpoint.V4, peer.Endpoint.V6
	// Same trimming as usque's register command: "1.2.3.4:0" and "[::1]:0".
	if len(v4) < 3 || len(v6) < 4 {
		return fmt.Errorf("unexpected endpoint format %q / %q", v4, v6)
	}
	cfg := config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(priv),
		EndpointV4:     v4[:len(v4)-2],
		EndpointV6:     v6[1 : len(v6)-3],
		EndpointH2V4:   config.DefaultEndpointH2V4,
		EndpointH2V6:   config.DefaultEndpointH2V6,
		EndpointPubKey: peer.PublicKey,
		ID:             updated.ID,
		AccessToken:    account.Token,
		IPv4:           updated.Config.Interface.Addresses.V4,
		IPv6:           updated.Config.Interface.Addresses.V6,
	}
	return saveConfig(path, cfg)
}

// saveConfig writes cfg to path. usque's SaveConfig ignores its receiver and
// encodes the global AppConfig, so cfg has to become AppConfig first; saving a
// local Config wrote every field blank.
func saveConfig(path string, cfg config.Config) error {
	mu.Lock()
	defer mu.Unlock()
	config.AppConfig = cfg
	if err := config.AppConfig.SaveConfig(path); err != nil {
		return err
	}
	// The file holds the device's private key.
	return os.Chmod(path, 0o600)
}

// SweepWarpSetLicense binds a WARP+ key to the registered device, as
// `usque account set` does.
//
//export SweepWarpSetLicense
func SweepWarpSetLicense(configPath, key *C.char) *C.char {
	cfg, err := load(C.GoString(configPath))
	if err != nil {
		return cError(err)
	}
	return cError(api.UpdateLicenceKey(cfg.ID, cfg.AccessToken, C.GoString(key)))
}

func load(path string) (config.Config, error) {
	mu.Lock()
	defer mu.Unlock()
	if err := config.LoadConfig(path); err != nil {
		return config.Config{}, err
	}
	return config.AppConfig, nil
}

// SweepWarpStart brings the MASQUE tunnel up on the extension's utun fd and
// keeps it up (reconnecting on every loss) until SweepWarpStop. Returns once
// the tunnel is being maintained; connection progress arrives as log lines.
//
//export SweepWarpStart
func SweepWarpStart(configPath, sni *C.char, tunFd C.int) *C.char {
	return cError(start(C.GoString(configPath), C.GoString(sni), int(tunFd)))
}

func start(path, sni string, fd int) error {
	if fd < 0 {
		return errors.New("no tunnel file descriptor")
	}
	cfg, err := load(path)
	if err != nil {
		return err
	}
	priv, err := cfg.GetEcPrivateKey()
	if err != nil {
		return err
	}
	peer, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		return err
	}
	cert, err := internal.GenerateCert(priv, &priv.PublicKey)
	if err != nil {
		return err
	}
	tlsConfig, err := api.PrepareTlsConfig(priv, peer, cert, sni, false)
	if err != nil {
		return err
	}
	endpoint, err := config.SelectEndpointFromConfig(true, false, 443)
	if err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		cancel()
	}
	ctx, c := context.WithCancel(context.Background())
	cancel = c
	go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig:       tlsConfig,
		KeepalivePeriod: keepalive,
		Endpoint:        endpoint,
		Device:          &utun{fd: fd},
		MTU:             mtu,
		ReconnectDelay:  reconnectDelay,
		AlwaysReconnect: true,
		UseHTTP2:        true,
	})
	log.Printf("WARP tunnel starting: endpoint %s, SNI %s", endpoint, sni)
	return nil
}

//export SweepWarpStop
func SweepWarpStop() {
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		cancel()
		cancel = nil
	}
}

// utun is the extension's tunnel interface. Darwin utun frames every packet
// with a 4-byte address-family header.
type utun struct {
	fd int
	// usque's per-cycle read lock does not span reconnects, so a reader from
	// the previous session can still be parked in read(2) when the next one
	// starts. Both share rbuf.
	rmu   sync.Mutex
	rbuf  [4 + 65535]byte
	wpool sync.Pool
}

func (t *utun) ReadPacket(buf []byte) (int, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	for {
		n, err := unix.Read(t.fd, t.rbuf[:])
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return 0, err
		}
		if n <= 4 {
			continue
		}
		// IPv6 does not route inside this MASQUE session (measured on macOS,
		// 2026-09-12: stuck in-tunnel v6 traffic took the whole session down).
		// The extension still claims the v6 default route so nothing leaks
		// around the tunnel; dropping it here keeps it out of the session and
		// apps fall back to IPv4.
		if t.rbuf[4]>>4 != 4 {
			continue
		}
		if n-4 > len(buf) {
			continue // larger than the tunnel MTU we configured; cannot carry it
		}
		return copy(buf, t.rbuf[4:n]), nil
	}
}

func (t *utun) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	var family uint32
	switch pkt[0] >> 4 {
	case 4:
		family = unix.AF_INET
	case 6:
		family = unix.AF_INET6
	default:
		return nil
	}
	bp, _ := t.wpool.Get().(*[]byte)
	if bp == nil {
		b := make([]byte, 0, 4+65535)
		bp = &b
	}
	b := binary.BigEndian.AppendUint32((*bp)[:0], family)
	b = append(b, pkt...)
	_, err := unix.Write(t.fd, b)
	*bp = b
	t.wpool.Put(bp)
	if err == unix.EINTR || err == unix.ENOBUFS {
		return nil // a dropped packet, not a dead device
	}
	return err
}

// FindTunnelFd returns the utun control socket NetworkExtension created for
// this process. NEPacketTunnelFlow does not expose it, so scan the descriptor
// table for the socket whose UTUN_OPT_IFNAME answers.
//
//export SweepWarpFindTunnelFd
func SweepWarpFindTunnelFd() C.int {
	const sysprotoControl, utunOptIfname = 2, 2
	for fd := 0; fd < 1024; fd++ {
		name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
		if err == nil && strings.HasPrefix(name, "utun") {
			return C.int(fd)
		}
	}
	return -1
}

func main() {}
