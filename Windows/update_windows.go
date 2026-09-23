//go:build windows

package main

import (
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
// snoozed all look the same to the user. force is the window's "Check for
// updates", which does report what it found.
func (a *app) checkForUpdate(force bool) {
	if !force && snoozed(time.Now()) {
		return
	}
	a.mu.Lock()
	if a.installing || a.updateState == "checking" {
		a.mu.Unlock()
		return
	}
	if force {
		a.updateState, a.updateError = "checking", ""
	}
	a.mu.Unlock()
	a.changed()

	client := &http.Client{Timeout: 20 * time.Second}
	update, err := LatestUpdate(client, releasesFeed, version)
	a.mu.Lock()
	switch {
	case err != nil:
		if force {
			a.updateState, a.updateError = "failed", "Could not check for updates: "+err.Error()
		}
	case update == nil:
		if force {
			a.updateState = "uptodate"
		}
	default:
		a.update, a.updateState, a.updateError = update, "idle", ""
	}
	if !force && a.updateState == "checking" {
		a.updateState = "idle"
	}
	a.mu.Unlock()
	if err != nil {
		a.logf("update check failed: %v", err)
	}
	a.changed()

	// The window shows a banner, like the Mac. Someone working from the tray
	// only would never see it, so they still get asked.
	if update != nil && !force && !a.ui.visible() {
		if msgBox("Sweep VPN "+update.Version+" is available. Update now?",
			windows.MB_YESNO|windows.MB_ICONINFORMATION) == idYes {
			a.installUpdate()
		} else {
			a.snoozeUpdate()
		}
	}
}

func (a *app) snoozeUpdate() {
	snooze(time.Now())
	a.mu.Lock()
	a.update, a.updateState, a.updateError = nil, "idle", ""
	a.mu.Unlock()
	a.changed()
}

func (a *app) updateFailed(msg string) {
	a.mu.Lock()
	a.installing, a.updateState, a.updateError = false, "failed", msg
	a.mu.Unlock()
	a.alert(msg)
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
	if update == nil || a.installing {
		a.mu.Unlock() // nothing to install, or a click while one is running
		return
	}
	a.installing, a.updateState, a.updateError = true, "downloading", ""
	a.mu.Unlock()
	a.changed()

	client := &http.Client{Timeout: 10 * time.Minute}
	payload, err := DownloadUpdate(client, update)
	if err != nil {
		a.updateFailed("Could not install the update: " + err.Error())
		return
	}

	dir := filepath.Join(a.dataDir, "updates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		a.updateFailed("Could not install the update: " + err.Error())
		return
	}
	staged := filepath.Join(dir, "SweepVPN-"+update.Version+".exe")
	if err := os.WriteFile(staged, payload, 0o755); err != nil {
		a.updateFailed("Could not install the update: " + err.Error())
		return
	}

	old := a.exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(a.exe, old); err != nil {
		a.updateFailed("Could not replace Sweep VPN: " + err.Error())
		return
	}
	if err := os.Rename(staged, a.exe); err != nil {
		_ = os.Rename(old, a.exe) // put ourselves back rather than leave a hole
		a.updateFailed("Could not replace Sweep VPN: " + err.Error())
		return
	}

	// Only now, with the new build in place, put the network back the way we
	// found it: the new process starts clean, and a failed swap above left
	// this one still routing. The new process waits for our mutex.
	a.onExit()
	if err := exec.Command(a.exe).Start(); err != nil {
		msgBox("Updated, but could not restart: start Sweep VPN again from the Start menu.",
			windows.MB_ICONWARNING)
	}
	systray.Quit()
}

// clearOldExe removes the copy the previous version left behind. It can only
// succeed once that process is gone, which it is by the time we run.
func clearOldExe(exe string) { _ = os.Remove(exe + ".old") }
