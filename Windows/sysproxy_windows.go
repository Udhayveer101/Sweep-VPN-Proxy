package main

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The per-user WinINet proxy — what Settings ▸ Network ▸ Proxy edits. Edge,
// Chrome, Windows apps and most programs follow it; no admin rights needed.
// Like the Mac's system SOCKS switch it only captures apps that honour the
// system proxy, and UDP (most games, QUIC) does not go through it.
const inetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
const appKey = `Software\SweepVPN`

var bypass = "<local>;localhost;127.*;10.*;192.168.*;172.16.*;172.17.*;172.18.*;172.19.*;" + "172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*"

func openKey(path string) (registry.Key, error) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	return k, err
}

// SetSystemProxy points Windows at 127.0.0.1:port, remembering what was there
// so turning it off puts the user's own settings back.
func SetSystemProxy(port int) error {
	inet, err := openKey(inetKey)
	if err != nil {
		return err
	}
	defer inet.Close()
	app, err := openKey(appKey)
	if err != nil {
		return err
	}
	defer app.Close()

	if active, _, _ := app.GetIntegerValue("ProxyActive"); active != 1 {
		enable, _, _ := inet.GetIntegerValue("ProxyEnable")
		server, _, _ := inet.GetStringValue("ProxyServer")
		override, _, _ := inet.GetStringValue("ProxyOverride")
		_ = app.SetDWordValue("SavedProxyEnable", uint32(enable))
		_ = app.SetStringValue("SavedProxyServer", server)
		_ = app.SetStringValue("SavedProxyOverride", override)
	}
	if err := app.SetDWordValue("ProxyActive", 1); err != nil {
		return err
	}
	if err := inet.SetStringValue("ProxyServer", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		return err
	}
	_ = inet.SetStringValue("ProxyOverride", bypass)
	if err := inet.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	notifyProxyChanged()
	return nil
}

// RestoreSystemProxy undoes SetSystemProxy. A no-op when we never set it, so
// it is safe to call at every start (after a crash or a shutdown with it on).
func RestoreSystemProxy() error {
	app, err := openKey(appKey)
	if err != nil {
		return err
	}
	defer app.Close()
	if active, _, _ := app.GetIntegerValue("ProxyActive"); active != 1 {
		return nil
	}
	inet, err := openKey(inetKey)
	if err != nil {
		return err
	}
	defer inet.Close()
	enable, _, _ := app.GetIntegerValue("SavedProxyEnable")
	server, _, _ := app.GetStringValue("SavedProxyServer")
	override, _, _ := app.GetStringValue("SavedProxyOverride")
	if err := inet.SetDWordValue("ProxyEnable", uint32(enable)); err != nil {
		return err
	}
	restoreString(inet, "ProxyServer", server)
	restoreString(inet, "ProxyOverride", override)
	_ = app.SetDWordValue("ProxyActive", 0)
	notifyProxyChanged()
	return nil
}

func restoreString(k registry.Key, name, v string) {
	if v == "" {
		_ = k.DeleteValue(name)
	} else {
		_ = k.SetStringValue(name, v)
	}
}

// SystemProxyIsOurs reports whether Windows currently points at our listener.
func SystemProxyIsOurs(port int) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	enable, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	return enable == 1 && server == fmt.Sprintf("127.0.0.1:%d", port)
}

var (
	wininet           = windows.NewLazySystemDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

// Tells running programs to re-read the proxy settings now.
func notifyProxyChanged() {
	const settingsChanged, refresh = 39, 37
	internetSetOption.Call(0, settingsChanged, 0, 0)
	internetSetOption.Call(0, refresh, 0, 0)
}

func getBool(name string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, appKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, _ := k.GetIntegerValue(name)
	return v == 1
}

// getBoolDefault is getBool for settings that default to on.
func getBoolDefault(name string, def bool) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, appKey, registry.QUERY_VALUE)
	if err != nil {
		return def
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return def
	}
	return v == 1
}

func setBool(name string, on bool) {
	k, err := openKey(appKey)
	if err != nil {
		return
	}
	defer k.Close()
	v := uint32(0)
	if on {
		v = 1
	}
	_ = k.SetDWordValue(name, v)
}

func getString(name string) string {
	k, err := registry.OpenKey(registry.CURRENT_USER, appKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue(name)
	return v
}

func setString(name, v string) {
	k, err := openKey(appKey)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetStringValue(name, v)
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func startsWithWindows() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("SweepVPN")
	return err == nil
}

// setStartWithWindows also covers a shutdown with routing on: at the next
// sign-in the app starts and either routes again or puts the proxy back.
func setStartWithWindows(on bool, exe string) error {
	k, err := openKey(runKey)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue("SweepVPN"); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	return k.SetStringValue("SweepVPN", `"`+exe+`" -background`)
}

// armRestoreAtSignIn: if Windows shuts down while routing is on (the app gets
// no chance to clean up), RunOnce puts the user's proxy back at the next
// sign-in so their internet is not left pointing at a closed port.
func armRestoreAtSignIn(on bool, exe string) {
	k, err := openKey(`Software\Microsoft\Windows\CurrentVersion\RunOnce`)
	if err != nil {
		return
	}
	defer k.Close()
	if on {
		_ = k.SetStringValue("SweepVPNRestoreProxy", `"`+exe+`" -restore-proxy`)
	} else {
		_ = k.DeleteValue("SweepVPNRestoreProxy")
	}
}
