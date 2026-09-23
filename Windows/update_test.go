package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func feed(t *testing.T, releases ...ghRelease) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(releases)
	}))
}

func release(tag string, assets ...string) ghRelease {
	r := ghRelease{TagName: tag}
	for _, name := range assets {
		r.Assets = append(r.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}{Name: name, URL: "https://example.invalid/" + name})
	}
	return r
}

func TestOffersANewerRelease(t *testing.T) {
	srv := feed(t, release("windows-v1.4.0",
		"SweepVPN-1.4.0-windows-x64.exe", "SweepVPN-1.4.0-windows-x64.exe.sha256"))
	defer srv.Close()

	got, err := LatestUpdate(srv.Client(), srv.URL, "1.0.0")
	if err != nil || got == nil {
		t.Fatalf("expected an update, got %v %v", got, err)
	}
	if got.Version != "1.4.0" || !strings.HasSuffix(got.Digest, ".sha256") {
		t.Fatalf("wrong update: %+v", got)
	}
}

// Both products publish into one release list. Offering the macOS DMG here
// would hand the user a file Windows cannot run.
func TestIgnoresTheMacTag(t *testing.T) {
	srv := feed(t, release("v9.9.9", "SweepVPN-9.9.9.dmg", "SweepVPN-9.9.9.dmg.sha256"))
	defer srv.Close()

	got, _ := LatestUpdate(srv.Client(), srv.URL, "1.0.0")
	if got != nil {
		t.Fatalf("offered a macOS build: %+v", got)
	}
}

func TestSameVersionIsNotAnUpdate(t *testing.T) {
	srv := feed(t, release("windows-v1.0.0",
		"SweepVPN-1.0.0-windows-x64.exe", "SweepVPN-1.0.0-windows-x64.exe.sha256"))
	defer srv.Close()

	if got, _ := LatestUpdate(srv.Client(), srv.URL, "1.0.0"); got != nil {
		t.Fatalf("offered the version already running: %+v", got)
	}
}

func TestPicksTheHighestNotTheLast(t *testing.T) {
	srv := feed(t,
		release("windows-v1.10.0", "SweepVPN-1.10.0-windows-x64.exe", "SweepVPN-1.10.0-windows-x64.exe.sha256"),
		release("windows-v1.9.0", "SweepVPN-1.9.0-windows-x64.exe", "SweepVPN-1.9.0-windows-x64.exe.sha256"))
	defer srv.Close()

	got, _ := LatestUpdate(srv.Client(), srv.URL, "1.0.0")
	if got == nil || got.Version != "1.10.0" {
		t.Fatalf("wrong pick: %+v", got)
	}
}

func TestReleaseWithoutAChecksumIsSkipped(t *testing.T) {
	srv := feed(t, release("windows-v1.4.0", "SweepVPN-1.4.0-windows-x64.exe"))
	defer srv.Close()

	if got, _ := LatestUpdate(srv.Client(), srv.URL, "1.0.0"); got != nil {
		t.Fatalf("offered an unverifiable download: %+v", got)
	}
}

func TestDraftsAndPrereleasesAreSkipped(t *testing.T) {
	draft := release("windows-v2.0.0", "SweepVPN-2.0.0-windows-x64.exe", "SweepVPN-2.0.0-windows-x64.exe.sha256")
	draft.Draft = true
	srv := feed(t, draft)
	defer srv.Close()

	if got, _ := LatestUpdate(srv.Client(), srv.URL, "1.0.0"); got != nil {
		t.Fatalf("offered a draft: %+v", got)
	}
}

func TestVersionOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.10.0", "1.9.0", true},
		{"1.4", "1.3.9", true},
		{"1.4.0", "1.4", false},
		{"1.0.0", "1.0.0", false},
		{"nonsense", "1.0.0", false},
	}
	for _, c := range cases {
		if got := isNewer(c.a, c.b); got != c.want {
			t.Errorf("isNewer(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// The whole point of the checksum: a download that does not match it is never
// written anywhere it could be run.
func TestDownloadRefusesAMismatch(t *testing.T) {
	payload := []byte("not the real installer")
	wrong := sha256.Sum256([]byte("something else"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			_, _ = w.Write([]byte(hex.EncodeToString(wrong[:]) + "  SweepVPN.exe\n"))
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	_, err := DownloadUpdate(srv.Client(), &Update{
		Asset: srv.URL + "/SweepVPN.exe", Digest: srv.URL + "/SweepVPN.exe.sha256"})
	if err == nil {
		t.Fatal("accepted an installer that did not match its checksum")
	}
}

func TestDownloadAcceptsAMatch(t *testing.T) {
	payload := []byte("the real installer")
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  SweepVPN.exe\n"))
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	got, err := DownloadUpdate(srv.Client(), &Update{
		Asset: srv.URL + "/SweepVPN.exe", Digest: srv.URL + "/SweepVPN.exe.sha256"})
	if err != nil || string(got) != string(payload) {
		t.Fatalf("rejected a good download: %v", err)
	}
}
