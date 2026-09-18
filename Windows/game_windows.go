//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Gaming mode routes the whole PC through WARP at the packet level.
//
// The tray app's normal mode sets a WinINet proxy, which only apps that read
// that setting use. Games do not: they send gameplay over UDP, which this ISP
// drops outright, so they bypass the tunnel entirely. A wintun device catches
// every packet instead, and MASQUE CONNECT-IP carries the UDP inside one
// ordinary HTTPS flow.
//
// Needs administrator rights (wintun and the routing table), so the tray app
// re-launches itself elevated when the user turns this on.

const masqueEndpoint = "162.159.198.2"

// GameRoutes owns every routing-table change gaming mode makes, so teardown is
// exactly the inverse of setup and a crash cannot strand the PC on a dead
// tunnel.
type GameRoutes struct {
	iface   string // wintun interface name, e.g. "usque"
	gateway string // the physical default gateway, restored on the way out
	applied bool
}

// IsElevated reports whether this process can change the routing table.
func IsElevated() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid); err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

// RelaunchElevated restarts this executable with a UAC prompt, passing -game so
// the new instance comes up with gaming mode already on. Returns once the
// prompt is answered; the caller should exit if it succeeded.
func RelaunchElevated(extraArgs ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := strings.Join(append([]string{"-game"}, extraArgs...), " ")

	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(args)

	// SW_SHOWNORMAL; the tray icon is the visible result.
	return windows.ShellExecute(0, verb, file, params, nil, 1)
}

// DefaultGateway returns the current IPv4 default gateway and its interface
// index, before any tunnel route exists.
func DefaultGateway() (gateway string, err error) {
	out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output()
	if err != nil {
		return "", fmt.Errorf("route print: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// "0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.20  25"
		if len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && f[2] != "On-link" {
			return f[2], nil
		}
	}
	return "", fmt.Errorf("no IPv4 default gateway")
}

// Apply points the default route at the tunnel.
//
// Two halves rather than replacing the default route: they win on
// longest-prefix match, so the original default stays untouched and teardown
// is a delete instead of a restore.
func (g *GameRoutes) Apply(iface, gateway string) error {
	g.iface, g.gateway = iface, gateway

	// The tunnel's own packets must keep using the physical link, or they
	// would route into the tunnel they carry.
	if err := run("route", "add", masqueEndpoint, "mask", "255.255.255.255", gateway); err != nil {
		return fmt.Errorf("pin MASQUE endpoint: %w", err)
	}
	g.applied = true

	for _, half := range [][2]string{{"0.0.0.0", "128.0.0.0"}, {"128.0.0.0", "128.0.0.0"}} {
		if err := run("netsh", "interface", "ipv4", "add", "route",
			half[0]+"/1", iface, "store=active"); err != nil {
			_ = g.Remove()
			return fmt.Errorf("route %s via %s: %w", half[0], iface, err)
		}
	}

	if err := run("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+iface, "static", "1.1.1.1", "primary"); err != nil {
		// DNS is a comfort, not a requirement: the tunnel still carries
		// queries to whatever resolver the system already had.
		return nil
	}
	return nil
}

// Remove undoes everything Apply did. Safe to call twice and on a partial
// setup, so every failure path can call it unconditionally.
func (g *GameRoutes) Remove() error {
	if !g.applied {
		return nil
	}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Routes first: leaving the split default while the tunnel goes away
	// would black-hole the PC.
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		note(run("netsh", "interface", "ipv4", "delete", "route", half, g.iface, "store=active"))
	}
	note(run("route", "delete", masqueEndpoint))
	g.applied = false
	return firstErr
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "),
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// WaitForInterface blocks until the wintun device exists and has an address,
// or the deadline passes. usque creates it asynchronously after launch.
func WaitForInterface(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("netsh", "interface", "ipv4", "show", "addresses",
			"name="+name).Output()
		if err == nil && strings.Contains(string(out), "IP Address") {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("interface %q never came up", name)
}
