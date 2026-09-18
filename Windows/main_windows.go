package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
)

// usque.exe is the patched usque built by build.sh (Tools/usque patches).
//
//go:embed usque.exe
var usqueBinary []byte

var version = "dev"

const proxyPort = 1080

type app struct {
	exe, dataDir, config, usque string
	log                         io.Writer
	warp                        *Warp

	mu      sync.Mutex
	enabled bool
	proxyOn bool

	gameOn   bool
	gameRoutes GameRoutes

	update *Update

	mStatus, mRoute, mGame, mSetup, mStartup, mUpdate *systray.MenuItem
}

func main() {
	restore := flag.Bool("restore-proxy", false, "put back the proxy settings Sweep changed, then exit")
	game := flag.Bool("game", false, "start with gaming mode on (set by the elevated relaunch)")
	flag.Parse()
	startInGameMode = *game

	name, _ := windows.UTF16PtrFromString(`Local\SweepVPN`)
	_, err := windows.CreateMutex(nil, false, name)
	running := err == windows.ERROR_ALREADY_EXISTS
	if *restore {
		if !running {
			_ = RestoreSystemProxy()
		}
		return
	}
	if running {
		msgBox("Sweep VPN is already running. Look for its icon in the taskbar tray (click ^ near the clock).", windows.MB_ICONINFORMATION)
		return
	}

	a, err := newApp()
	if err != nil {
		msgBox("Sweep VPN could not start: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	systray.Run(a.onReady, a.onExit)
}

func newApp() (*app, error) {
	exe, _ := os.Executable()
	roaming, err := os.UserConfigDir() // %APPDATA%
	if err != nil {
		return nil, err
	}
	local, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return nil, err
	}
	a := &app{exe: exe, dataDir: filepath.Join(local, "SweepVPN"),
		config: filepath.Join(roaming, "SweepVPN", "warp", "config.json")}
	if err := os.MkdirAll(a.dataDir, 0o700); err != nil {
		return nil, err
	}
	logPath := filepath.Join(a.dataDir, "sweep.log")
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 5<<20 {
		_ = os.Remove(logPath)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	a.log = f

	// The previous version renamed itself aside so we could take its place.
	clearOldExe(a.exe)

	sum := sha256.Sum256(usqueBinary)
	a.usque = filepath.Join(a.dataDir, "usque-"+hex.EncodeToString(sum[:4])+".exe")
	if fi, err := os.Stat(a.usque); err != nil || fi.Size() != int64(len(usqueBinary)) {
		if err := os.WriteFile(a.usque, usqueBinary, 0o700); err != nil {
			return nil, fmt.Errorf("could not unpack WARP: %w", err)
		}
	}
	a.warp = &Warp{Exe: a.usque, Config: a.config, SNI: "example.com", Port: proxyPort, Log: f, OnState: a.onWarpState}
	fmt.Fprintf(f, "%s sweep %s started\n", time.Now().Format("2006-01-02 15:04:05"), version)
	return a, nil
}

func (a *app) registered() bool {
	_, err := os.Stat(a.config)
	return err == nil
}

func (a *app) onReady() {
	// A crash or shutdown while routing leaves the proxy pointing at a closed
	// port; put the user's settings back before anything else.
	_ = RestoreSystemProxy()
	armRestoreAtSignIn(false, a.exe)

	systray.SetIcon(icon(140, 140, 140))
	systray.SetTitle("Sweep VPN")
	systray.SetTooltip("Sweep VPN")
	a.mStatus = systray.AddMenuItem("Off", "")
	a.mStatus.Disable()
	systray.AddSeparator()
	a.mRoute = systray.AddMenuItemCheckbox("Route this PC through WARP", "Send all traffic that uses the Windows proxy through Cloudflare WARP", false)
	a.mGame = systray.AddMenuItemCheckbox("Gaming mode", "Send everything, games and their UDP included, through WARP. Needs administrator rights.", false)
	a.mSetup = systray.AddMenuItem("Set up WARP…", "Register this PC with Cloudflare WARP (free, no account)")
	info := systray.AddMenuItem(fmt.Sprintf("Proxy for single apps: 127.0.0.1:%d (HTTP)", proxyPort), "")
	info.Disable()
	systray.AddSeparator()
	a.mStartup = systray.AddMenuItemCheckbox("Start with Windows", "", startsWithWindows())
	a.mUpdate = systray.AddMenuItem("Update available…", "Download and install a newer version of Sweep VPN")
	a.mUpdate.Hide()
	mLog := systray.AddMenuItem("Open log", "")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit Sweep VPN", "")
	a.refreshSetup()

	if startInGameMode && a.registered() {
		go a.setGameMode(true)
	} else if getBool("Enabled") && a.registered() {
		a.setEnabled(true)
	} else if !a.registered() {
		a.mStatus.SetTitle("WARP is not set up — choose Set up WARP…")
	}

	// Quiet unless there is something to offer; the ticker is for the PCs
	// that stay signed in for weeks.
	go func() {
		a.checkForUpdate(false)
		for range time.Tick(snoozeInterval) {
			a.checkForUpdate(false)
		}
	}()

	go func() {
		for {
			select {
			case <-a.mRoute.ClickedCh:
				a.setEnabled(!a.mRoute.Checked())
			case <-a.mGame.ClickedCh:
				go a.setGameMode(!a.mGame.Checked())
			case <-a.mUpdate.ClickedCh:
				go a.installUpdate()
			case <-a.mSetup.ClickedCh:
				go a.setup()
			case <-a.mStartup.ClickedCh:
				on := !a.mStartup.Checked()
				if err := setStartWithWindows(on, a.exe); err != nil {
					msgBox("Could not change Start with Windows: "+err.Error(), windows.MB_ICONERROR)
				} else if on {
					a.mStartup.Check()
				} else {
					a.mStartup.Uncheck()
				}
			case <-mLog.ClickedCh:
				open(filepath.Join(a.dataDir, "sweep.log"))
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func (a *app) onExit() {
	a.mu.Lock()
	a.enabled = false // no late Running re-arms the proxy
	if a.proxyOn {
		a.proxyOn = false
		_ = RestoreSystemProxy()
	}
	armRestoreAtSignIn(false, a.exe)
	wasGame := a.gameOn
	a.gameOn = false
	a.mu.Unlock()
	// Routes outlive the process unless we take them down, which would leave
	// the PC pointed at a tunnel that no longer exists.
	if wasGame {
		_ = a.gameRoutes.Remove()
	}
	a.warp.Stop()
}

// startInGameMode is set by the elevated relaunch, which passes -game.
var startInGameMode bool

// setGameMode routes the whole PC through WARP at the packet level.
//
// Gaming mode and the proxy mode both claim the same traffic, so turning one
// on takes the other down first. It needs administrator rights for wintun and
// the routing table; without them the app relaunches itself through UAC.
func (a *app) setGameMode(on bool) {
	if on && !a.registered() {
		a.mGame.Uncheck()
		go a.setup()
		return
	}

	if on && !IsElevated() {
		if err := RelaunchElevated(); err != nil {
			a.mGame.Uncheck()
			msgBox("Gaming mode needs administrator rights: "+err.Error(), windows.MB_ICONERROR)
			return
		}
		systray.Quit() // the elevated instance takes over
		return
	}

	if !on {
		a.mu.Lock()
		a.gameOn = false
		a.mu.Unlock()
		a.warp.Stop()
		if err := a.gameRoutes.Remove(); err != nil {
			msgBox("Could not put the routing back: "+err.Error(), windows.MB_ICONERROR)
		}
		a.mGame.Uncheck()
		a.mStatus.SetTitle("Off")
		return
	}

	// The proxy mode must go first: two things claiming the same traffic is
	// how a machine ends up routing in a circle.
	a.setEnabled(false)

	gateway, err := DefaultGateway()
	if err != nil {
		msgBox("Gaming mode needs a network connection: "+err.Error(), windows.MB_ICONERROR)
		a.mGame.Uncheck()
		return
	}

	a.mu.Lock()
	a.gameOn = true
	a.mu.Unlock()
	a.mGame.Check()
	a.mStatus.SetTitle("Gaming mode starting…")

	a.warp.Game = true
	a.warp.Start()

	if err := WaitForInterface(gameInterface, 30*time.Second); err != nil {
		a.warp.Stop()
		a.mGame.Uncheck()
		a.mu.Lock(); a.gameOn = false; a.mu.Unlock()
		msgBox("The tunnel interface never came up: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	if err := a.gameRoutes.Apply(gameInterface, gateway); err != nil {
		a.warp.Stop()
		a.mGame.Uncheck()
		a.mu.Lock(); a.gameOn = false; a.mu.Unlock()
		msgBox("Could not route through the tunnel: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	a.mStatus.SetTitle("Gaming mode on")
}

// gameInterface is the wintun device name usque creates for nativetun.
const gameInterface = "usque"

func (a *app) refreshSetup() {
	if a.registered() {
		a.mSetup.SetTitle("WARP is set up")
		a.mSetup.Disable()
	} else {
		a.mSetup.SetTitle("Set up WARP…")
		a.mSetup.Enable()
	}
}

func (a *app) setEnabled(on bool) {
	if on && !a.registered() {
		a.mRoute.Uncheck()
		go a.setup()
		return
	}
	setBool("Enabled", on)
	if on {
		a.mu.Lock()
		a.enabled = true
		a.mu.Unlock()
		a.mRoute.Check()
		a.warp.Start()
		return
	}
	a.mu.Lock()
	a.enabled = false
	var err error
	if a.proxyOn {
		a.proxyOn = false
		err = RestoreSystemProxy()
		armRestoreAtSignIn(false, a.exe)
	}
	a.mu.Unlock()
	a.mRoute.Uncheck()
	if err != nil {
		msgBox("Could not put the Windows proxy settings back: "+err.Error(), windows.MB_ICONERROR)
	}
	a.warp.Stop()
}

// onWarpState turns the Windows proxy on only once WARP is listening. After
// that it stays on through reconnects: a connection refused while WARP comes
// back is better than traffic quietly leaving outside it (same as the Mac).
func (a *app) onWarpState(s State, msg string) {
	a.mu.Lock()
	enabled := a.enabled
	if enabled && s == Running && !a.proxyOn {
		if err := SetSystemProxy(proxyPort); err != nil {
			msg = "could not set the Windows proxy: " + err.Error()
			s = Failed
		} else {
			a.proxyOn = true
			armRestoreAtSignIn(true, a.exe)
		}
	}
	a.mu.Unlock()

	title := s.String()
	switch {
	case s == Running && enabled:
		title = "Connected — this PC goes through WARP"
		systray.SetIcon(icon(52, 199, 89))
	case s == Running:
		title = "WARP ready"
		systray.SetIcon(icon(52, 199, 89))
	case s == Starting:
		title = "Connecting…"
		systray.SetIcon(icon(255, 159, 10))
	case s == Failed:
		title = "Problem: " + msg
		systray.SetIcon(icon(255, 59, 48))
	default:
		systray.SetIcon(icon(140, 140, 140))
	}
	a.mStatus.SetTitle(truncate(title, 90))
	systray.SetTooltip(truncate("Sweep VPN — "+title, 120))

	// Never give up while the user wants to be connected.
	if s == Failed && enabled {
		time.AfterFunc(15*time.Second, func() {
			a.mu.Lock()
			still := a.enabled
			a.mu.Unlock()
			if still && a.warp.State() == Failed && a.registered() {
				a.warp.Start()
			}
		})
	}
}

func (a *app) setup() {
	if a.registered() {
		return
	}
	ok := msgBox("Sweep VPN uses Cloudflare WARP. It is free and needs no account: this PC gets its own anonymous WARP identity.\n\n"+
		"By continuing you accept Cloudflare's terms:\nhttps://www.cloudflare.com/application/terms/\n\nRegister this PC now?",
		windows.MB_YESNO|windows.MB_ICONQUESTION) == 6 // IDYES
	if !ok {
		return
	}
	a.mSetup.SetTitle("Registering…")
	a.mSetup.Disable()
	err := Register(a.usque, a.config, "", "")
	a.refreshSetup()
	if err != nil {
		fmt.Fprintf(a.log, "%s register failed: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		msgBox(err.Error(), windows.MB_ICONERROR)
		return
	}
	a.mStatus.SetTitle("WARP is set up")
	if msgBox("WARP is set up. Route this PC through WARP now?", windows.MB_YESNO|windows.MB_ICONINFORMATION) == 6 {
		a.setEnabled(true)
	}
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func msgBox(text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("Sweep VPN")
	r, _ := windows.MessageBox(0, t, c, flags|windows.MB_SETFOREGROUND)
	return r
}

func open(path string) {
	verb, _ := windows.UTF16PtrFromString("open")
	p, _ := windows.UTF16PtrFromString(path)
	_ = windows.ShellExecute(0, verb, p, nil, nil, windows.SW_SHOWNORMAL)
}
