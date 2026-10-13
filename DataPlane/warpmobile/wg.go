package main

// Gaming mode on iOS: the tunnel over WireGuard instead of MASQUE, which is
// what `usque wgtun` gives macOS (Tools/usque/wgtun.patch). A WireGuard session
// is not tied to the client's address, so it survives the change of public
// address that ends every TCP connection, the HTTP/2 MASQUE flow included.
//
// wgIdentity, uapi, wgStats, wgLogger and the watcher loop are copies of
// cmd/wgtun_darwin.go in that patch: it is package cmd, which cannot be
// imported from here. Keep them in step. The decisions themselves
// (api.WarpBind, api.WgWatch) are shared.

import "C"

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// The same values as wgtun's flag defaults on macOS. Junk stays at 3 or more:
// the gateway this is built for cuts a flow that starts with a bare handshake.
const (
	wgPort             = 2408
	wgJunk             = 4
	wgKeepalive        = 5 * time.Second
	wgHandshakeTimeout = 8 * time.Second
)

// wgAPI is where registrations go; a variable so a test can stand in for it.
var wgAPI = internal.ApiUrl + "/" + internal.ApiVersion

// wgIdentity is a WARP registration made with a curve25519 key: the API's
// answer as it came, plus the private key the registration was made with.
type wgIdentity struct {
	PrivateKey string `json:"private_key"`
	Config     struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// uapi returns the wireguard-go configuration, device and peer apart (the
// watcher replaces the peer), and what the tunnel needs besides it: the inner
// address and WARP's reserved bytes.
func (id *wgIdentity) uapi(port int, keepalive time.Duration) (dev, peerConf, addr string, reserved [3]byte, err error) {
	key := func(name, b64 string) (string, error) {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != 32 {
			return "", fmt.Errorf("identity: %s is not a 32-byte base64 key", name)
		}
		return hex.EncodeToString(raw), nil
	}
	if len(id.Config.Peers) == 0 {
		return "", "", "", reserved, errors.New("identity: no peer")
	}
	peer := id.Config.Peers[0]
	priv, err := key("private_key", id.PrivateKey)
	if err != nil {
		return "", "", "", reserved, err
	}
	pub, err := key("peer public_key", peer.PublicKey)
	if err != nil {
		return "", "", "", reserved, err
	}
	// The API gives the address with a zero port ("162.159.192.3:0").
	host, _, err := net.SplitHostPort(peer.Endpoint.V4)
	if err != nil || net.ParseIP(host).To4() == nil {
		return "", "", "", reserved, fmt.Errorf("identity: bad peer endpoint %q", peer.Endpoint.V4)
	}
	addr = id.Config.Interface.Addresses.V4
	if net.ParseIP(addr).To4() == nil {
		return "", "", "", reserved, fmt.Errorf("identity: bad interface address %q", addr)
	}
	if cid, err := base64.StdEncoding.DecodeString(id.Config.ClientID); err == nil && len(cid) == 3 {
		copy(reserved[:], cid)
	}
	dev = fmt.Sprintf("private_key=%s\n", priv)
	peerConf = fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\nallowed_ip=0.0.0.0/0\n",
		pub, net.JoinHostPort(host, strconv.Itoa(port)), int(keepalive.Seconds()))
	return dev, peerConf, addr, reserved, nil
}

// SweepWarpRegisterWG makes the WireGuard registration gaming mode needs and
// writes it to identityPath; it does nothing when one is already there. It is
// a second anonymous device under the terms the user accepted for the first.
// Returns NULL or an error string the caller frees with SweepWarpFree.
//
//export SweepWarpRegisterWG
func SweepWarpRegisterWG(identityPath *C.char) *C.char {
	return cError(registerWG(C.GoString(identityPath)))
}

func registerWG(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("could not generate a WireGuard key: %w", err)
	}
	serial, err := internal.GenerateRandomAndroidSerial()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(models.Registration{
		Key:     base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
		Tos:     internal.TimeAsCfString(time.Now()),
		Model:   internal.DefaultModel,
		Serial:  serial,
		KeyType: internal.KeyTypeWg,
		TunType: internal.TunTypeWg,
		Locale:  internal.DefaultLocale,
	})
	answer, err := wgCall(http.MethodPost, "/reg", "", body)
	if err != nil {
		return fmt.Errorf("WireGuard registration failed: %w", err)
	}
	var device struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	identity := map[string]json.RawMessage{}
	if err := json.Unmarshal(answer, &identity); err != nil {
		return fmt.Errorf("WireGuard registration: unreadable answer: %w", err)
	}
	_ = json.Unmarshal(answer, &device)
	// A new registration comes back with WARP off. Best effort: the identity
	// is good either way, and a tunnel that cannot open falls back to MASQUE.
	if _, err := wgCall(http.MethodPatch, "/reg/"+device.ID, device.Token, []byte(`{"warp_enabled":true}`)); err != nil {
		log.Printf("WireGuard registration: could not switch WARP on: %v", err)
	}
	identity["private_key"], _ = json.Marshal(base64.StdEncoding.EncodeToString(key.Bytes()))
	out, _ := json.Marshal(identity)
	var check wgIdentity
	if err := json.Unmarshal(out, &check); err != nil {
		return fmt.Errorf("WireGuard registration: unreadable answer: %w", err)
	}
	if _, _, _, _, err := check.uapi(wgPort, wgKeepalive); err != nil {
		return fmt.Errorf("WireGuard registration: %w", err)
	}
	// The file holds the device's private key.
	return os.WriteFile(path, out, 0o600)
}

func wgCall(method, path, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, wgAPI+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Called while the app shows "Connecting": never the default, which has no timeout.
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return answer, nil
}

func wgStats(dev *device.Device) (c api.WgCounters) {
	out, err := dev.IpcGet()
	if err != nil {
		return c
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "tx_bytes":
			c.Tx, _ = strconv.ParseUint(v, 10, 64)
		case "rx_bytes":
			c.Rx, _ = strconv.ParseUint(v, 10, 64)
		case "last_handshake_time_sec":
			c.Handshake, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return c
}

// wgLogger passes on one wireguard-go error every 30s. It reports each packet
// it cannot send, several a second for as long as the network is away, and
// every line here is a synchronous journal append inside the extension.
func wgLogger() *device.Logger {
	var last atomic.Int64
	return &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(format string, args ...any) {
			now := time.Now().Unix()
			if was := last.Load(); now-was >= 30 && last.CompareAndSwap(was, now) {
				log.Printf("wireguard: "+format, args...)
			}
		},
	}
}

// wgTun wraps the extension's utun for wireguard-go, which closes its TUN when
// the device closes. The fd is NetworkExtension's, and the MASQUE fallback
// still needs it, so wireguard-go gets a duplicate (as WireGuard's own iOS
// app does).
func wgTun(fd int) (tun.Device, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		_ = unix.Close(dup)
		return nil, err
	}
	// 0: the MTU is NetworkExtension's to set. Closes the file on failure.
	return tun.CreateTUNFromFile(os.NewFile(uintptr(dup), "utun"), 0)
}

// openWG brings WireGuard up on tunDev and returns once a handshake has
// completed. On any failure the device is closed, tunDev with it, and the
// caller carries on over MASQUE. tunnelAddr is the address the tunnel
// interface was given, from the MASQUE registration.
func openWG(ctx context.Context, identityPath, tunnelAddr string, makeTun func() (tun.Device, error)) (*device.Device, string, error) {
	raw, err := os.ReadFile(identityPath)
	if err != nil {
		return nil, "", errors.New("no WireGuard registration")
	}
	var id wgIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, "", errors.New("the WireGuard registration is unreadable")
	}
	devConf, peerConf, addr, reserved, err := id.uapi(wgPort, wgKeepalive)
	if err != nil {
		return nil, "", err
	}
	// Two registrations, one interface: WARP hands every device the same
	// inner IPv4 address, and this stops the day it does not.
	if addr != tunnelAddr {
		return nil, "", errors.New("the WireGuard registration has a different tunnel address")
	}
	tunDev, err := makeTun()
	if err != nil {
		return nil, "", fmt.Errorf("tunnel interface: %w", err)
	}
	wg := device.NewDevice(tunDev, &api.WarpBind{Bind: conn.NewStdNetBind(), Reserved: reserved, Junk: wgJunk}, wgLogger())
	if err := wg.IpcSet(devConf + peerConf); err != nil {
		wg.Close()
		return nil, "", err
	}
	if err := wg.Up(); err != nil {
		wg.Close()
		return nil, "", err
	}
	// The persistent keepalive starts a handshake at once.
	log.Printf("Establishing WireGuard session on UDP %d", wgPort)
	deadline := time.Now().Add(wgHandshakeTimeout)
	for wgStats(wg).Handshake == 0 {
		if ctx.Err() != nil || time.Now().After(deadline) {
			wg.Close()
			return nil, "", fmt.Errorf("no handshake within %s", wgHandshakeTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return wg, peerConf, nil
}

// wgWatch keeps the tunnel on a live path until ctx ends: a new socket when
// its flow has died, a new session when the old one has expired. It never
// gives up, since a network that is simply down looks the same from here.
// ponytail: a network that starts blocking WireGuard mid-session leaves the
// tunnel held until it is restarted (which then falls back to MASQUE). Hand
// over to MASQUE here if that is ever seen.
func wgWatch(ctx context.Context, wg *device.Device, peerConf string) {
	var w api.WgWatch
	pending := api.WgKeep
	// One line when the path dies and one when it is back, however long that takes.
	var downAt, retryAt time.Time
	var rxAtDown uint64
	tick := time.NewTicker(time.Second / api.WgReadings)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if time.Now().Before(retryAt) {
			continue
		}
		now := wgStats(wg)
		if !downAt.IsZero() && now.Handshake != 0 && now.Rx > rxAtDown {
			log.Printf("WireGuard path restored after %.1fs", time.Since(downAt).Seconds())
			downAt = time.Time{}
		}
		if act := w.Step(now, time.Now()); act != api.WgKeep {
			pending = act
			if downAt.IsZero() {
				downAt, rxAtDown = time.Now(), now.Rx
				if act == api.WgNewSession {
					log.Println("WireGuard session expired or never completed; starting a new one on a new socket")
				} else {
					// The handshake's age tells a stall that follows a rekey (every 120s) from one that does not.
					log.Printf("No reply for %.0fs, last handshake %ds ago; moving the WireGuard session to a new socket", w.Quiet.Seconds(), time.Now().Unix()-now.Handshake)
				}
			}
		}
		if pending == api.WgKeep {
			continue
		}
		conf := "listen_port=0\n"
		if pending == api.WgNewSession {
			conf += "replace_peers=true\n" + peerConf
		}
		// Retried every second until it works: with no socket nothing is
		// sent, and a tunnel that sends nothing never looks stalled again.
		if err := wg.IpcSet(conf); err != nil {
			log.Printf("Failed to open a new socket: %v", err)
			retryAt = time.Now().Add(time.Second)
			continue
		}
		if pending == api.WgNewSession {
			rxAtDown = 0 // the replaced peer counts from zero; not before, or a failed reopen reads as restored
		}
		pending = api.WgKeep
	}
}
