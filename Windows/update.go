package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The updater: find a newer build on the project's GitHub releases, verify it
// against the checksum the release publishes, and swap this exe for it.
//
// No update server to run and no signing key to manage: the releases API is the
// feed and the published .sha256 is the integrity check. This half is
// deliberately OS-independent so it is testable without a Windows machine.

const releasesFeed = "https://api.github.com/repos/Udhayveer101/Sweep-VPN-Proxy/releases?per_page=30"

// windowsTagPrefix keeps this app from offering itself a macOS DMG: both
// products publish into the same release list, so /releases/latest is
// whichever was tagged last and cannot be used.
const windowsTagPrefix = "windows-v"

const snoozeInterval = 24 * time.Hour

type Update struct {
	Version string
	Notes   string
	Asset   string // installer download URL
	Digest  string // URL of its .sha256
}

type ghRelease struct {
	TagName    string `json:"tag_name"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// LatestUpdate returns the newest release that beats current, or nil.
func LatestUpdate(client *http.Client, feed, current string) (*Update, error) {
	req, err := http.NewRequest(http.MethodGet, feed, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("releases: HTTP %d", resp.StatusCode)
	}
	var releases []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}
	return pickUpdate(releases, current), nil
}

func pickUpdate(releases []ghRelease, current string) *Update {
	best := current
	var found *Update
	for _, r := range releases {
		if r.Draft || r.Prerelease || !strings.HasPrefix(r.TagName, windowsTagPrefix) {
			continue
		}
		v := strings.TrimPrefix(r.TagName, windowsTagPrefix)
		if !isNewer(v, best) {
			continue
		}
		var asset, digest string
		for _, a := range r.Assets {
			if strings.HasSuffix(a.Name, ".exe") {
				asset = a.URL
			}
		}
		for _, a := range r.Assets {
			// The digest must belong to the installer we picked, not to some
			// other asset that happens to end in .sha256.
			if strings.HasSuffix(a.Name, ".exe.sha256") {
				digest = a.URL
			}
		}
		if asset == "" || digest == "" {
			continue
		}
		best = v
		found = &Update{Version: v, Notes: r.Body, Asset: asset, Digest: digest}
	}
	return found
}

// isNewer compares dotted numeric versions component by component. A missing
// component counts as 0, and anything unparsable sorts lowest, so a malformed
// tag can never look like an upgrade.
func isNewer(a, b string) bool {
	x, y := semver(a), semver(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			return p > q
		}
	}
	return false
}

func semver(s string) []int {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = -1
		}
		out[i] = n
	}
	return out
}

// fetchAll reads a whole response body with a sane ceiling, so a hostile or
// broken host cannot make us allocate without bound.
func fetchAll(client *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// expectedDigest pulls the hex digest out of `shasum -a 256` output:
// "<hex>  <filename>".
func expectedDigest(b []byte) (string, error) {
	fields := strings.Fields(string(b))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return "", fmt.Errorf("unreadable checksum file")
	}
	hexed := strings.ToLower(fields[0])
	if _, err := hex.DecodeString(hexed); err != nil {
		return "", fmt.Errorf("unreadable checksum file")
	}
	return hexed, nil
}

// DownloadUpdate fetches the installer and refuses it unless it matches the
// published checksum. An unverified exe is never written where it could be run.
func DownloadUpdate(client *http.Client, u *Update) ([]byte, error) {
	payload, err := fetchAll(client, u.Asset, 200<<20)
	if err != nil {
		return nil, err
	}
	raw, err := fetchAll(client, u.Digest, 4<<10)
	if err != nil {
		return nil, err
	}
	want, err := expectedDigest(raw)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(payload)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("the downloaded update did not match its published checksum")
	}
	return payload, nil
}
