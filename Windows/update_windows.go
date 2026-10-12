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
	if !force && !updateNow && snoozed(time.Now()) {
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
	case !force && update.Version == getString(failedVersionValue):
		// It already failed to start on this PC. Offering it again every day
		// would restart Sweep every day; "Check for updates" still finds it.
		update = nil
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
	if update != nil && updateNow {
		a.installUpdate()
		return
	}
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

// The new version sets this event once it is up; the old one waits for it
// before it lets go.
const updateOKKey = `Local\SweepVPNUpdateOK`

const (
	failedVersionValue = "UpdateFailedVersion" // not offered again unprompted
	noticeValue        = "UpdateNotice"        // shown once at the next start
)

var confirmTimeout = 45 * time.Second

// installUpdate downloads the new exe, checks it against the published
// checksum and that it runs, swaps it in, and hands over to it.
//
// Nothing about the installed app changes until the download has passed both
// checks. After the swap the old build is kept beside the new one until the new
// process reports that it started; if it never does, the old build goes back
// and is started again, so a bad release cannot leave the PC without Sweep.
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
	a.logf("update: downloading %s", update.Version)

	client := &http.Client{Timeout: 10 * time.Minute}
	payload, err := DownloadUpdate(client, update)
	if err != nil {
		a.updateFailed("Could not download the update: " + err.Error())
		return
	}
	a.mu.Lock()
	a.updateState = "installing"
	a.mu.Unlock()
	a.changed()

	// Beside the exe, not in the data folder: the swap is a rename, and a
	// rename cannot cross drives. It also finds out now, before anything has
	// changed, whether this folder can be written at all.
	staged := a.exe + ".new"
	if err := os.WriteFile(staged, payload, 0o755); err != nil {
		_ = os.Remove(staged)
		a.updateFailed("Sweep VPN cannot update itself in " + filepath.Dir(a.exe) +
			" (" + err.Error() + "). Move it to a folder you can write to, such as Downloads, and try again.")
		return
	}
	if err := reportsVersion(staged, update.Version); err != nil {
		_ = os.Remove(staged)
		a.updateFailed("The downloaded version was not installed: " + err.Error() + ".")
		return
	}
	if err := swapExe(a.exe, staged); err != nil {
		_ = os.Remove(staged)
		a.updateFailed("Could not replace Sweep VPN: " + err.Error())
		return
	}

	// Only now, with the new build in place, put the network back the way we
	// found it: the new process starts clean, and a failure above left this
	// one still routing.
	name, _ := windows.UTF16PtrFromString(updateOKKey)
	ev, _ := windows.CreateEvent(nil, 1, 0, name)
	a.onExit()
	releaseInstance() // the new process takes the single-instance mutex
	cmd := exec.Command(a.exe, "-updated-from", version)
	started := cmd.Start() == nil
	if started && ev != 0 {
		s, _ := windows.WaitForSingleObject(ev, uint32(confirmTimeout/time.Millisecond))
		started = s == windows.WAIT_OBJECT_0
	}
	if started {
		a.logf("update: %s is running", update.Version)
		systray.Quit()
		return
	}

	a.logf("update: %s did not start; restoring %s", update.Version, version)
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait() // the exe cannot be renamed back while it runs
	}
	setString(failedVersionValue, update.Version)
	if err := rollbackExe(a.exe); err != nil {
		a.logf("update: rollback failed: %v", err)
		msgBox("Sweep VPN "+update.Version+" did not start and the previous version could not be put back ("+
			err.Error()+"). Download Sweep VPN again from its releases page.", windows.MB_ICONERROR)
		systray.Quit()
		return
	}
	setString(noticeValue, "Version "+update.Version+" did not start, so the previous version was restored.")
	_ = exec.Command(a.exe).Start()
	systray.Quit()
}

// confirmUpdate is the new version telling the old one it is up, which is
// what lets the old one exit instead of rolling back.
func confirmUpdate(from string) {
	name, _ := windows.UTF16PtrFromString(updateOKKey)
	if h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name); err == nil {
		_ = windows.SetEvent(h)
		windows.CloseHandle(h)
	}
	setString(failedVersionValue, "")
	setString(noticeValue, "Updated from version "+from+" to "+version+".")
	// The old process is still exiting; its file can go once it has.
	exe, _ := os.Executable()
	time.AfterFunc(5*time.Second, func() { clearOldExe(exe) })
}

// clearOldExe removes the copy the previous version left behind. It can only
// succeed once that process is gone.
func clearOldExe(exe string) {
	_ = os.Remove(exe + ".old")
	_ = os.Remove(exe + ".new") // an install that was interrupted before the swap
}
