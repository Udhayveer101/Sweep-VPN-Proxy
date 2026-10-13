//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The pin must be the address wgtun dials, or the tunnel's own packets route
// into the tunnel. The API gives it with a zero port.
func TestWireGuardEndpointReadsTheRegistration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg-warp.json")
	cases := map[string]string{
		`{"config":{"peers":[{"endpoint":{"v4":"162.159.192.3:0"}}]}}`: "162.159.192.3",
		`{"config":{"peers":[{"endpoint":{"v4":"not-an-ip:0"}}]}}`:     "",
		`{"config":{"peers":[]}}`:                                      "",
		`half a file`:                                                  "",
	}
	for body, want := range cases {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := WireGuardEndpoint(path); got != want {
			t.Fatalf("%s: got %q, want %q", body, got, want)
		}
	}
	if got := WireGuardEndpoint(filepath.Join(t.TempDir(), "missing.json")); got != "" {
		t.Fatalf("a missing registration gave %q", got)
	}
}
