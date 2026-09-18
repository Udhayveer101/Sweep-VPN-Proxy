//go:build windows

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The Windows half of the updater: when to ask, and how to put the new exe in
// place of this one.

const snoozeValue = "UpdateSnoozeUntil"

// MessageBox's "Yes"; x/sys/windows does not define the IDxxx replies.
const idYes = 6

func snoozed(now time.Time) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, appKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	s, _, err := k.GetStringValue(snoozeValue)
	if err != nil {
		return false
	}
	unix, err := strconv.ParseInt(s, 10, 64)
	return err == nil && now.Before(time.Unix(unix, 0))
}

func snooze(now time.Time) {
	k, err := openKey(appKey)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetStringValue(snoozeValue, strconv.FormatInt(now.Add(snoozeInterval).Unix(), 10))
}

// checkForUpdate runs in the background at startup and once a day after that.
// It is silent unless there is something to offer: offline, up to date and
// snoozed all look the same to the user.
func (a *app) checkForUpdate(force bool) {
	if !force && snoozed(time.Now()) {
		return
	}
	client := &http.Client{Timeout: 20 * time.Second}
	update, err := LatestUpdate(client, releasesFeed, version)
	if err != nil || update == nil {
		if err != nil {
			fmt.Fprintf(a.log, "%s update check failed: %v\n",
				time.Now().Format("2006-01-02 15:04:05"), err)
		}
		return
	}

	a.mu.Lock()
	a.update = update
	a.mu.Unlock()
	a.mUpdate.SetTitle("Update to " + update.Version + "…")
	a.mUpdate.Show()

	if msgBox("Sweep VPN "+update.Version+" is available. Update now?",
		windows.MB_YESNO|windows.MB_ICONINFORMATION) == idYes {
		a.installUpdate()
	} else {
		snooze(time.Now())
	}
}

// installUpdate downloads the new exe, checks it against the published
// checksum, then swaps it in and restarts.
//
// Windows lets a running exe be renamed but not overwritten, which is what
// makes this possible without an installer: move ourselves aside, put the new
// build at our path, start it and quit. The leftover .old is deleted at the
// next start, when nothing holds it open any more.
func (a *app) installUpdate() {
	a.mu.Lock()
	update := a.update
	a.mu.Unlock()
	if update == nil {
		return
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	payload, err := DownloadUpdate(client, update)
	if err != nil {
		msgBox("Could not install the update: "+err.Error(), windows.MB_ICONERROR)
		return
	}

	dir := filepath.Join(a.dataDir, "updates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		msgBox("Could not install the update: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	staged := filepath.Join(dir, "SweepVPN-"+update.Version+".exe")
	if err := os.WriteFile(staged, payload, 0o755); err != nil {
		msgBox("Could not install the update: "+err.Error(), windows.MB_ICONERROR)
		return
	}

	// Put the network back the way we found it before the swap: the new
	// process starts clean, and a failure here cannot strand the PC on a
	// tunnel owned by an exe that no longer exists.
	a.onExit()

	old := a.exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(a.exe, old); err != nil {
		msgBox("Could not replace Sweep VPN: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	if err := os.Rename(staged, a.exe); err != nil {
		_ = os.Rename(old, a.exe) // put ourselves back rather than leave a hole
		msgBox("Could not replace Sweep VPN: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	if err := exec.Command(a.exe).Start(); err != nil {
		msgBox("Updated, but could not restart: start Sweep VPN again from the Start menu.",
			windows.MB_ICONWARNING)
	}
	systray.Quit()
}

// clearOldExe removes the copy the previous version left behind. It can only
// succeed once that process is gone, which it is by the time we run.
func clearOldExe(exe string) { _ = os.Remove(exe + ".old") }
