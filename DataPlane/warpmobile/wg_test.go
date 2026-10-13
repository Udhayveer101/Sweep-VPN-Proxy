package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func wgTestKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// The registration is what `usque wgtun --identity` reads on macOS: the API's
// answer plus the private key whose public half was registered.
func TestRegisterWG(t *testing.T) {
	peer := wgTestKey(t)
	var posted, patched map[string]any
	var bearer string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/reg":
			_ = json.Unmarshal(body, &posted)
			fmt.Fprintf(w, `{"id":"dev1","token":"tok1","warp_enabled":false,"config":{"client_id":"AQID",
				"peers":[{"public_key":%q,"endpoint":{"v4":"162.159.192.3:0"}}],
				"interface":{"addresses":{"v4":"172.16.0.2"}}}}`, b64(peer.PublicKey().Bytes()))
		case r.Method == http.MethodPatch && r.URL.Path == "/reg/dev1":
			bearer = r.Header.Get("Authorization")
			_ = json.Unmarshal(body, &patched)
			fmt.Fprint(w, `{}`)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()
	defer func(was string) { wgAPI = was }(wgAPI)
	wgAPI = srv.URL

	path := filepath.Join(t.TempDir(), "wg-warp.json")
	if err := registerWG(path); err != nil {
		t.Fatal(err)
	}
	if posted["key_type"] != "curve25519" || posted["tunnel_type"] != "wireguard" || posted["tos"] == "" {
		t.Fatalf("registered as %v, want a curve25519 WireGuard device with the terms accepted", posted)
	}
	if bearer != "Bearer tok1" || patched["warp_enabled"] != true {
		t.Fatalf("WARP switched on with %q %v, want the device's token and warp_enabled", bearer, patched)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("identity is %v, want 0600: it holds a private key", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	var id wgIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		t.Fatal(err)
	}
	priv, _ := base64.StdEncoding.DecodeString(id.PrivateKey)
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil || b64(key.PublicKey().Bytes()) != posted["key"] {
		t.Fatalf("saved private key does not match the registered public key (%v)", err)
	}
	_, peerConf, addr, reserved, err := id.uapi(wgPort, wgKeepalive)
	if err != nil || addr != "172.16.0.2" || reserved != [3]byte{1, 2, 3} {
		t.Fatalf("uapi = %q %v %v, want the tunnel address and the client id as reserved bytes", addr, reserved, err)
	}
	if want := "endpoint=162.159.192.3:2408\n"; !strings.Contains(peerConf, want) {
		t.Fatalf("peer config %q lacks %q", peerConf, want)
	}

	// Already registered: a second call must not make a second device.
	if err := registerWG(path); err != nil || calls != 2 {
		t.Fatalf("second registerWG = %v after %d calls, want no new request", err, calls)
	}
}

// Whatever keeps WireGuard from being used must be an error before the tunnel
// interface is touched, so the caller's MASQUE fallback finds it as it was.
func TestOpenWGRefusesBeforeTouchingTheTunnel(t *testing.T) {
	dir := t.TempDir()
	noTun := func() (tun.Device, error) { t.Fatal("opened the tunnel interface"); return nil, nil }
	if _, _, err := openWG(context.Background(), filepath.Join(dir, "missing.json"), "172.16.0.2", noTun); err == nil {
		t.Fatal("no registration, want an error")
	}
	path := wgTestIdentity(t, dir, wgTestKey(t), wgTestKey(t).PublicKey(), "127.0.0.1:0")
	if _, _, err := openWG(context.Background(), path, "172.16.0.9", noTun); err == nil {
		t.Fatal("registration for another tunnel address, want an error")
	}
}

func wgTestIdentity(t *testing.T, dir string, key *ecdh.PrivateKey, peer *ecdh.PublicKey, endpoint string) string {
	t.Helper()
	var id wgIdentity
	id.PrivateKey = b64(key.Bytes())
	id.Config.Peers = append(id.Config.Peers, struct {
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			V4 string `json:"v4"`
		} `json:"endpoint"`
	}{PublicKey: b64(peer.Bytes())})
	id.Config.Peers[0].Endpoint.V4 = endpoint
	id.Config.Interface.Addresses.V4 = "172.16.0.2"
	raw, _ := json.Marshal(id)
	path := filepath.Join(dir, "wg-warp.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The whole path short of the real utun: openWG against a wireguard-go peer on
// loopback, junk packets and all, then the watcher ending when asked.
func TestOpenWGHandshakesAndWatchStops(t *testing.T) {
	client, server := wgTestKey(t), wgTestKey(t)
	serverTun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("172.16.0.1")}, nil, mtu)
	if err != nil {
		t.Fatal(err)
	}
	peer := device.NewDevice(serverTun, conn.NewStdNetBind(), &device.Logger{Verbosef: func(string, ...any) {}, Errorf: t.Logf})
	defer peer.Close()
	if err := peer.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=172.16.0.2/32\n",
		hex.EncodeToString(server.Bytes()), wgPort, hex.EncodeToString(client.PublicKey().Bytes()))); err != nil {
		t.Skipf("UDP %d is not free here: %v", wgPort, err)
	}
	if err := peer.Up(); err != nil {
		t.Skipf("UDP %d is not free here: %v", wgPort, err)
	}

	path := wgTestIdentity(t, t.TempDir(), client, server.PublicKey(), "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg, peerConf, err := openWG(ctx, path, "172.16.0.2", func() (tun.Device, error) {
		dev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("172.16.0.2")}, nil, mtu)
		return dev, err
	})
	if err != nil {
		t.Fatalf("openWG: %v", err)
	}
	defer wg.Close()
	if wgStats(wg).Handshake == 0 {
		t.Fatal("openWG returned without a handshake")
	}

	done := make(chan struct{})
	go func() { wgWatch(ctx, wg, peerConf); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wgWatch outlived its context: SweepWarpStop would leave the device open")
	}
}
