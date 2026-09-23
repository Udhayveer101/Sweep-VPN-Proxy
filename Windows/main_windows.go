package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
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

const (
	defaultSNI  = "example.com"
	rotateTTL   = "90s" // GameModeController.Disguise.rotate.flowTTL
	instanceKey = `Local\SweepVPN`
	showKey     = `Local\SweepVPNShow`
)

type app struct {
	exe, dataDir, config, usque string
	log                         *rotatingLog
	warp                        *Warp
	ui                          *window

	mu      sync.Mutex
	enabled bool // the user wants this PC routed through the proxy
	proxyOn bool // the Windows proxy currently points at us

	warpState State
	warpMsg   string

	gameOn    bool   // the user wants gaming mode
	gameState string // stopped | starting | running | failed
	gameMsg   string
	gameBusy  bool
	gameGW    string
	routesMu  sync.Mutex // serialises route changes; they shell out
	routes    GameRoutes

	proxyError, lastError string
	setupBusy             bool
	setupError            string

	update      *Update
	updateState string // idle | checking | uptodate | downloading | failed
	updateError string
	installing  bool

	mStatus, mRoute, mGame, mSetup, mStartup, mUpdate *systray.MenuItem
}

func main() {
	restore := flag.Bool("restore-proxy", false, "put back the proxy settings Sweep changed, then exit")
	game := flag.Bool("game", false, "start with gaming mode on (set by the elevated relaunch)")
	background := flag.Bool("background", false, "start in the tray without opening the window (Start with Windows)")
	flag.Parse()
	startInGameMode = *game
	enableDPIAwareness()

	name, _ := windows.UTF16PtrFromString(instanceKey)
	if *restore {
		// Only look: creating the mutex here would make a "Start with Windows"
		// launch racing this one at sign-in believe Sweep was already running.
		if h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name); err == nil {
			windows.CloseHandle(h)
		} else if err != windows.ERROR_ACCESS_DENIED {
			_ = RestoreSystemProxy()
		}
		return
	}

	// An update or the UAC relaunch starts us while the old process is still
	// on its way out, so wait for it briefly before calling it a second copy.
	var owned bool
	for i := 0; i < 25 && !owned; i++ {
		h, err := windows.CreateMutex(nil, false, name)
		switch {
		case err == nil:
			owned = true
		case h != 0:
			windows.CloseHandle(h)
		}
		if !owned {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if !owned {
		// Bring the running copy's window forward instead of a dead-end dialog.
		// An elevated copy (gaming mode) is out of reach from here.
		ev, _ := windows.UTF16PtrFromString(showKey)
		if h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, ev); err == nil {
			_ = windows.SetEvent(h)
			windows.CloseHandle(h)
		} else {
			msgBox("Sweep VPN is already running (as administrator, for gaming mode). Look for its icon near the clock.", windows.MB_ICONINFORMATION)
		}
		return
	}

	a, err := newApp()
	if err != nil {
		msgBox("Sweep VPN could not start: "+err.Error(), windows.MB_ICONERROR)
		return
	}
	openAtStart = !*background || startInGameMode
	systray.Run(a.onReady, a.onExit)
}

// openAtStart: a normal launch opens the window like the Mac app; Start with
// Windows starts quietly in the tray.
var openAtStart bool

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
		config:    filepath.Join(roaming, "SweepVPN", "warp", "config.json"),
		gameState: "stopped", updateState: "idle"}
	if err := os.MkdirAll(a.dataDir, 0o700); err != nil {
		return nil, err
	}
	if a.log, err = openRotatingLog(filepath.Join(a.dataDir, "sweep.log")); err != nil {
		return nil, err
	}

	// The previous version renamed itself aside so we could take its place.
	clearOldExe(a.exe)

	sum := sha256.Sum256(usqueBinary)
	a.usque = filepath.Join(a.dataDir, "usque-"+hex.EncodeToString(sum[:4])+".exe")
	if fi, err := os.Stat(a.usque); err != nil || fi.Size() != int64(len(usqueBinary)) {
		if err := os.WriteFile(a.usque, usqueBinary, 0o700); err != nil {
			return nil, fmt.Errorf("could not unpack WARP: %w", err)
		}
	}
	a.warp = &Warp{Exe: a.usque, Config: a.config, SNI: a.sni(), Port: proxyPort, Log: a.log, OnState: a.onWarpState}
	a.logf("sweep %s started", version)
	return a, nil
}

func (a *app) logf(format string, args ...any) {
	fmt.Fprintf(a.log, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", args...)
}

func (a *app) registered() bool {
	_, err := os.Stat(a.config)
	return err == nil
}

func (a *app) sni() string {
	if s := getString("SNI"); s != "" {
		return s
	}
	return defaultSNI
}

func (a *app) flowTTL() string {
	if getBool("GameRotate") {
		return rotateTTL
	}
	return "0"
}

func (a *app) onReady() {
	// A crash or shutdown while routing leaves the proxy pointing at a closed
	// port; put the user's settings back before anything else.
	_ = RestoreSystemProxy()
	armRestoreAtSignIn(false, a.exe)
	// 1.4 wrote the Run entry without -background; rewrite it so signing in
	// does not throw the window in the user's face.
	if startsWithWindows() {
		_ = setStartWithWindows(true, a.exe)
	}

	systray.SetIcon(icon(140, 140, 140))
	systray.SetTitle("Sweep VPN")
	systray.SetTooltip("Sweep VPN")
	systray.SetOnTapped(func() { a.ui.show() })
	mOpen := systray.AddMenuItem("Open Sweep VPN", "Show the Sweep VPN window")
	systray.AddSeparator()
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

	a.ui = newWindow(a)
	a.changed()

	if startInGameMode && a.registered() {
		go a.setGameMode(true)
	} else if getBool("Enabled") && a.registered() {
		go a.setEnabled(true)
	}
	if openAtStart {
		if !a.registered() {
			a.ui.openSheet("setup") // picked up when the page loads
		}
		go a.ui.show() // off the tray's thread: WebView2 takes a moment
	}
	go a.watchShowRequests()

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
			case <-mOpen.ClickedCh:
				a.ui.show()
			case <-a.mRoute.ClickedCh:
				go a.setEnabled(!a.mRoute.Checked())
			case <-a.mGame.ClickedCh:
				go a.setGameMode(!a.mGame.Checked())
			case <-a.mUpdate.ClickedCh:
				go a.installUpdate()
			case <-a.mSetup.ClickedCh:
				a.ui.show()
				a.ui.openSheet("setup")
			case <-a.mStartup.ClickedCh:
				a.setStartup(!a.mStartup.Checked())
			case <-mLog.ClickedCh:
				open(a.log.path)
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// watchShowRequests brings the window forward when Sweep is launched again.
func (a *app) watchShowRequests() {
	name, _ := windows.UTF16PtrFromString(showKey)
	ev, err := windows.CreateEvent(nil, 0, 0, name)
	if err != nil {
		return
	}
	for {
		if s, err := windows.WaitForSingleObject(ev, windows.INFINITE); err != nil || s != windows.WAIT_OBJECT_0 {
			return
		}
		a.ui.show()
	}
}

var exitOnce sync.Once

// onExit puts the network back the way the user had it. Safe to call twice:
// the updater calls it before the swap and systray calls it again on Quit.
func (a *app) onExit() {
	exitOnce.Do(func() {
		a.mu.Lock()
		a.enabled = false // no late Running re-arms the proxy
		if a.proxyOn {
			a.proxyOn = false
			_ = RestoreSystemProxy()
		}
		armRestoreAtSignIn(false, a.exe)
		a.gameOn = false
		a.mu.Unlock()
		a.warp.Stop()
		// Routes outlive the process unless we take them down, which would
		// leave the PC pointed at a tunnel that no longer exists.
		a.routesMu.Lock()
		_ = a.routes.Remove()
		a.routesMu.Unlock()
	})
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
		a.changed()
		a.ui.show()
		a.ui.openSheet("setup")
		return
	}
	a.mu.Lock()
	if a.gameBusy {
		a.mu.Unlock()
		a.changed()
		return
	}
	a.gameBusy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.gameBusy = false
		a.mu.Unlock()
		a.changed()
	}()

	if on && !IsElevated() {
		if err := RelaunchElevated(); err != nil {
			a.alert("Gaming mode needs administrator rights: " + err.Error())
			return
		}
		systray.Quit() // the elevated instance takes over
		return
	}

	if !on {
		a.stopGame()
		return
	}

	// The proxy mode must go first: two things claiming the same traffic is
	// how a machine ends up routing in a circle.
	a.stopProxy()

	gateway, err := DefaultGateway()
	if err != nil {
		a.alert("Gaming mode needs a network connection: " + err.Error())
		return
	}
	a.mu.Lock()
	a.gameOn, a.gameGW, a.gameState, a.gameMsg = true, gateway, "starting", ""
	a.mu.Unlock()
	a.changed()
	a.warp.SetMode(true, a.flowTTL(), a.sni())
	a.warp.Start() // onWarpState applies the routes once the device is up
}

func (a *app) stopGame() {
	a.mu.Lock()
	was := a.gameOn
	a.gameOn, a.gameState, a.gameMsg = false, "stopped", ""
	a.mu.Unlock()
	if !was {
		return
	}
	a.warp.Stop()
	a.warp.SetMode(false, "0", a.sni())
	a.routesMu.Lock()
	err := a.routes.Remove()
	a.routesMu.Unlock()
	if err != nil {
		a.alert("Could not put the routing back: " + err.Error())
	}
}

// applyGameRoutes points the PC at the tunnel. It runs on every Running, not
// just the first: a respawned or restarted usque builds a new wintun adapter,
// and Windows drops the routes that pointed at the old one.
func (a *app) applyGameRoutes() {
	a.routesMu.Lock()
	defer a.routesMu.Unlock()
	a.mu.Lock()
	on, gw := a.gameOn, a.gameGW
	a.mu.Unlock()
	if !on {
		return
	}
	err := WaitForInterface(gameInterface, 30*time.Second)
	if err == nil {
		_ = a.routes.Remove()
		err = a.routes.Apply(gameInterface, gw, MasqueEndpoint(a.config))
	}
	a.mu.Lock()
	still := a.gameOn
	if still && err == nil {
		a.gameState, a.gameMsg = "running", ""
	} else if still {
		a.gameState, a.gameMsg = "failed", "Could not route through the tunnel: "+err.Error()
	}
	a.mu.Unlock()
	if !still {
		_ = a.routes.Remove() // turned off while we were applying
	}
	if err != nil {
		a.logf("game routes: %v", err)
	}
	a.changed()
}

// gameInterface is the wintun device name usque creates for nativetun.
const gameInterface = "usque"

func (a *app) setEnabled(on bool) {
	if on && !a.registered() {
		a.changed()
		a.ui.show()
		a.ui.openSheet("setup")
		return
	}
	setBool("Enabled", on)
	if !on {
		a.stopProxy()
		a.warp.Stop()
		a.changed()
		return
	}
	a.stopGame()
	a.mu.Lock()
	a.enabled, a.proxyError = true, ""
	a.mu.Unlock()
	a.changed()
	a.warp.SetMode(false, "0", a.sni())
	a.warp.Start()
}

// stopProxy takes the Windows proxy down, leaving WARP to the caller.
func (a *app) stopProxy() {
	a.mu.Lock()
	a.enabled = false
	var err error
	if a.proxyOn {
		a.proxyOn = false
		err = RestoreSystemProxy()
		armRestoreAtSignIn(false, a.exe)
	}
	a.mu.Unlock()
	if err != nil {
		a.alert("Could not put the Windows proxy settings back: " + err.Error())
	}
}

// onWarpState turns the Windows proxy on only once WARP is listening. After
// that it stays on through reconnects: a connection refused while WARP comes
// back is better than traffic quietly leaving outside it (same as the Mac).
func (a *app) onWarpState(s State, msg string) {
	a.mu.Lock()
	a.warpState, a.warpMsg = s, msg
	enabled, game := a.enabled, a.gameOn
	if enabled && !game && s == Running && !a.proxyOn {
		if err := SetSystemProxy(proxyPort); err != nil {
			a.proxyError = "Could not set the Windows proxy: " + err.Error()
		} else {
			a.proxyOn, a.proxyError = true, ""
			armRestoreAtSignIn(true, a.exe)
		}
	}
	if game {
		switch s {
		case Starting:
			a.gameState = "starting"
		case Failed:
			a.gameState, a.gameMsg = "failed", msg
		}
	}
	a.mu.Unlock()
	a.changed()

	if game && s == Running {
		go a.applyGameRoutes()
	}
	// Never give up while the user wants to be connected.
	if s == Failed && (enabled || game) {
		time.AfterFunc(15*time.Second, func() {
			a.mu.Lock()
			still := a.enabled || a.gameOn
			a.mu.Unlock()
			if still && a.warp.State() == Failed && a.registered() {
				a.warp.Start()
			}
		})
	}
}

// statusLine is the one-line summary the tray and the window share.
func (a *app) statusLine() (title string, r, g, b byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gameOn {
		switch a.gameState {
		case "running":
			return "Gaming mode on: the whole PC goes through WARP", 52, 199, 89
		case "failed":
			return "Problem: " + a.gameMsg, 255, 59, 48
		}
		return "Gaming mode starting…", 255, 159, 10
	}
	if !a.registered() {
		return "WARP is not set up", 140, 140, 140
	}
	switch a.warpState {
	case Running:
		if a.proxyOn {
			return "Connected — this PC goes through WARP", 52, 199, 89
		}
		return fmt.Sprintf("WARP ready on 127.0.0.1:%d (SNI %s)", proxyPort, a.sni()), 52, 199, 89
	case Starting:
		return "Connecting to WARP… (SNI " + a.sni() + ")", 255, 159, 10
	case Failed:
		return "Problem: " + a.warpMsg, 255, 59, 48
	}
	return "Off", 140, 140, 140
}

// changed pushes the current state to the tray and the window. Cheap enough
// to call after every transition.
func (a *app) changed() {
	title, r, g, b := a.statusLine()
	systray.SetIcon(icon(r, g, b))
	systray.SetTooltip(truncate("Sweep VPN — "+title, 120))
	a.mStatus.SetTitle(truncate(title, 90))
	a.mu.Lock()
	enabled, game, update := a.enabled, a.gameOn, a.update
	a.mu.Unlock()
	check(a.mRoute, enabled)
	check(a.mGame, game)
	if a.registered() {
		a.mSetup.SetTitle("WARP is set up")
		a.mSetup.Disable()
	} else {
		a.mSetup.SetTitle("Set up WARP…")
		a.mSetup.Enable()
	}
	if update != nil {
		a.mUpdate.SetTitle("Update to " + update.Version + "…")
		a.mUpdate.Show()
	} else {
		a.mUpdate.Hide()
	}
	a.ui.push()
}

func check(m *systray.MenuItem, on bool) {
	if on {
		m.Check()
	} else {
		m.Uncheck()
	}
}

// alert shows an error in the window when it is open, where the Mac app shows
// it, and falls back to a dialog for someone working from the tray.
func (a *app) alert(msg string) {
	a.logf("alert: %s", msg)
	if a.ui.visible() {
		a.mu.Lock()
		a.lastError = msg
		a.mu.Unlock()
		a.changed()
		return
	}
	msgBox(msg, windows.MB_ICONERROR)
}

// register runs the one-time WARP setup (WarpSetupGuide on the Mac). The
// window only calls it after the user ticked Cloudflare's terms.
func (a *app) register(license, team string) {
	a.mu.Lock()
	if a.setupBusy {
		a.mu.Unlock()
		return
	}
	a.setupBusy, a.setupError = true, ""
	a.mu.Unlock()
	a.changed()
	err := Register(a.usque, a.config, license, team)
	a.mu.Lock()
	a.setupBusy = false
	if err != nil {
		a.setupError = err.Error()
	}
	a.mu.Unlock()
	if err != nil {
		a.logf("register failed: %v", err)
	}
	a.changed()
}

func (a *app) setStartup(on bool) {
	if err := setStartWithWindows(on, a.exe); err != nil {
		a.alert("Could not change Start with Windows: " + err.Error())
	}
	check(a.mStartup, startsWithWindows())
	a.changed()
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
