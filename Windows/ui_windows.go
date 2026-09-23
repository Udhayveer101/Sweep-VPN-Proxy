package main

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"fyne.io/systray"
	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// The app window: the same screens as the Mac app (HomeView, SettingsView,
// the WARP setup guide, the connection log), drawn by WebView2 from ui.html.
// WebView2 ships with Windows 11 and every updated Windows 10; without it the
// tray keeps working and the user is told how to get it.
//
// The window runs on its own locked OS thread with its own message loop, apart
// from the tray's. Closing it hides it (WARP keeps running, the tray reopens
// it) unless the user turned "keep running in the tray" off, in which case it
// quits the app like the Mac.

//go:embed ui.html
var uiHTML string

//go:embed appicon.png
var appIconPNG []byte

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procSetWindowLongPtr = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProc   = user32.NewProc("CallWindowProcW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetForeground    = user32.NewProc("SetForegroundWindow")
	procIsWindowVisible  = user32.NewProc("IsWindowVisible")
	procIsIconic         = user32.NewProc("IsIconic")
	procSendMessage      = user32.NewProc("SendMessageW")
	procCreateIconFrom   = user32.NewProc("CreateIconFromResourceEx")
	procGetDpiForSystem  = user32.NewProc("GetDpiForSystem")
	procSetDpiContext    = user32.NewProc("SetProcessDpiAwarenessContext")
)

const (
	gwlpWndProc = ^uintptr(3) // GWLP_WNDPROC (-4)
	wmClose     = 0x0010
	wmSetIcon   = 0x0080
	swHide      = 0
	swShow      = 5
	swRestore   = 9
)

// enableDPIAwareness keeps text sharp on scaled displays. Without it Windows
// bitmap-stretches the whole window at 125-200%.
func enableDPIAwareness() {
	if procSetDpiContext.Find() == nil {
		procSetDpiContext.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	}
}

func scaled(px int) int {
	if procGetDpiForSystem.Find() != nil {
		return px
	}
	dpi, _, _ := procGetDpiForSystem.Call()
	if dpi == 0 {
		return px
	}
	return px * int(dpi) / 96
}

type window struct {
	a *app

	once    sync.Once
	mu      sync.Mutex
	wv      webview2.WebView // nil until first shown, or if WebView2 is missing
	hwnd    uintptr
	failed  bool
	pending string  // a sheet asked for before the page finished loading
	orig    uintptr // WebView2's own window procedure, which we wrap
}

var theWindow *window // the subclassed procedure is a plain function

func newWindow(a *app) *window {
	w := &window{a: a}
	theWindow = w
	return w
}

// show creates the window on first use, then brings it forward.
func (w *window) show() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		ready := make(chan struct{})
		go w.run(ready)
		<-ready
	})
	w.mu.Lock()
	hwnd, failed := w.hwnd, w.failed
	w.mu.Unlock()
	if failed {
		if msgBox("The Sweep VPN window needs Microsoft Edge WebView2, which this PC is missing. Sweep keeps working from the tray icon near the clock.\n\nOpen the download page now?",
			windows.MB_YESNO|windows.MB_ICONINFORMATION) == idYes {
			open("https://go.microsoft.com/fwlink/p/?LinkId=2124703")
		}
		return
	}
	if r, _, _ := procIsIconic.Call(hwnd); r != 0 {
		procShowWindow.Call(hwnd, swRestore)
	} else {
		procShowWindow.Call(hwnd, swShow)
	}
	procSetForeground.Call(hwnd)
	w.push()
}

func (w *window) visible() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	hwnd := w.hwnd
	w.mu.Unlock()
	if hwnd == 0 {
		return false
	}
	r, _, _ := procIsWindowVisible.Call(hwnd)
	return r != 0
}

// run owns the window's thread for the life of the process.
func (w *window) run(ready chan struct{}) {
	runtime.LockOSThread()
	// An elevated instance (gaming mode) cannot share a profile folder written
	// by the unelevated one, so each gets its own.
	profile := "webview"
	if IsElevated() {
		profile = "webview-admin"
	}
	wv := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath: filepath.Join(w.a.dataDir, profile),
		WindowOptions: webview2.WindowOptions{
			Title: "Sweep VPN", Width: uint(scaled(460)), Height: uint(scaled(680)), Center: true,
		},
	})
	if wv == nil {
		w.mu.Lock()
		w.failed = true
		w.mu.Unlock()
		w.a.logf("window: WebView2 is not available")
		close(ready)
		return
	}
	hwnd := uintptr(wv.Window())
	wv.SetSize(scaled(420), scaled(620), webview2.HintMin)
	setWindowIcon(hwnd)
	w.orig, _, _ = procSetWindowLongPtr.Call(hwnd, gwlpWndProc, windows.NewCallback(subclassProc))

	// Bound calls run on this thread and block it, so anything slow goes
	// to its own goroutine and reports back through push.
	_ = wv.Bind("sweepAction", func(action, arg string) { go w.a.handle(action, arg) })
	_ = wv.Bind("sweepState", func() uiState { // the page asks once, when it loads
		s := w.a.snapshot()
		w.mu.Lock()
		s.Sheet, w.pending = w.pending, ""
		w.mu.Unlock()
		return s
	})
	_ = wv.Bind("sweepLog", func() string { return w.a.log.tail(96 << 10) })
	wv.SetHtml(uiHTML)

	w.mu.Lock()
	w.wv, w.hwnd = wv, hwnd
	w.mu.Unlock()
	close(ready)
	wv.Run()
}

// subclassProc hides the window instead of destroying it: WebView2 takes a
// second or two to start, and the tray is where the app lives between uses.
func subclassProc(hwnd, msg, wp, lp uintptr) uintptr {
	w := theWindow
	if w == nil {
		return 0
	}
	if msg == wmClose {
		if getBoolDefault("KeepInTray", true) {
			procShowWindow.Call(hwnd, swHide)
		} else {
			go systray.Quit()
		}
		return 0
	}
	r, _, _ := procCallWindowProc.Call(w.orig, hwnd, msg, wp, lp)
	return r
}

func setWindowIcon(hwnd uintptr) {
	if len(appIconPNG) == 0 {
		return
	}
	// PNG-compressed icon resources are accepted from Vista on.
	h, _, _ := procCreateIconFrom.Call(uintptr(unsafe.Pointer(&appIconPNG[0])), uintptr(len(appIconPNG)),
		1, 0x00030000, 0, 0, 0)
	if h != 0 {
		procSendMessage.Call(hwnd, wmSetIcon, 0, h) // small
		procSendMessage.Call(hwnd, wmSetIcon, 1, h) // big
	}
}

// push sends the current state to the page. A hidden window is skipped and
// catches up when shown, so a background app does no rendering work.
func (w *window) push() {
	if w == nil || !w.visible() {
		return
	}
	b, err := json.Marshal(w.a.snapshot())
	if err != nil {
		return
	}
	w.eval("typeof render==='function'&&render(" + string(b) + ")")
}

func (w *window) openSheet(name string) {
	if w == nil {
		return
	}
	// The page may still be loading, in which case the eval is dropped and
	// its first sweepState() picks the sheet up instead.
	w.mu.Lock()
	w.pending = name
	w.mu.Unlock()
	b, _ := json.Marshal(name)
	w.eval("typeof openSheet==='function'&&openSheet(" + string(b) + ")")
}

func (w *window) eval(js string) {
	w.mu.Lock()
	wv := w.wv
	w.mu.Unlock()
	if wv == nil {
		return
	}
	wv.Dispatch(func() { wv.Eval(js) })
}

// uiState is everything ui.html renders. Field names are its contract.
type uiState struct {
	Version     string `json:"version"`
	Registered  bool   `json:"registered"`
	Routing     bool   `json:"routing"`
	ProxyOn     bool   `json:"proxyOn"`
	Warp        string `json:"warp"`
	Status      string `json:"status"`
	ProxyError  string `json:"proxyError"`
	LastError   string `json:"lastError"`
	Game        bool   `json:"game"`
	GameState   string `json:"gameState"`
	GameStatus  string `json:"gameStatus"`
	GameBusy    bool   `json:"gameBusy"`
	Disguise    string `json:"disguise"`
	SNI         string `json:"sni"`
	Port        int    `json:"port"`
	Startup     bool   `json:"startup"`
	KeepInTray  bool   `json:"keepInTray"`
	Update      string `json:"update"`
	UpdateState string `json:"updateState"`
	UpdateError string `json:"updateError"`
	SetupBusy   bool   `json:"setupBusy"`
	SetupError  string `json:"setupError"`
	Sheet       string `json:"sheet,omitempty"`
}

func (a *app) snapshot() uiState {
	status, _, _, _ := a.statusLine()
	disguise := "standby"
	if getBool("GameRotate") {
		disguise = "rotate"
	}
	s := uiState{Version: version, Registered: a.registered(), SNI: a.sni(), Port: proxyPort,
		Startup: startsWithWindows(), KeepInTray: getBoolDefault("KeepInTray", true), Disguise: disguise}
	a.mu.Lock()
	defer a.mu.Unlock()
	s.Routing, s.ProxyOn = a.enabled, a.proxyOn
	s.Warp = [...]string{"stopped", "starting", "running", "failed"}[a.warpState]
	if a.enabled || a.gameOn || a.warpState != Stopped {
		s.Status = status
	}
	s.ProxyError, s.LastError = a.proxyError, a.lastError
	s.Game, s.GameState, s.GameBusy = a.gameOn, a.gameState, a.gameBusy
	if a.gameOn {
		s.GameStatus = status
	} else if a.gameBusy {
		s.GameStatus = "Waiting for Windows to grant administrator rights…"
	}
	if a.update != nil {
		s.Update = a.update.Version
	}
	s.UpdateState, s.UpdateError = a.updateState, a.updateError
	s.SetupBusy, s.SetupError = a.setupBusy, a.setupError
	return s
}

// handle runs one control from the page, off the window's thread.
func (a *app) handle(action, arg string) {
	on := arg == "true"
	switch action {
	case "setRouting":
		a.setEnabled(on)
	case "setGame":
		a.setGameMode(on)
	case "setDisguise":
		setBool("GameRotate", arg == "rotate")
	case "setSNI":
		// A hostname, nothing else: it goes on usque's command line.
		sni := strings.TrimSpace(arg)
		if sni == "" {
			sni = defaultSNI
		}
		if !validSNI(sni) {
			a.alert("That SNI is not a hostname. Use something like example.com.")
			break
		}
		setString("SNI", sni)
	case "setStartup":
		a.setStartup(on)
	case "setKeepInTray":
		setBool("KeepInTray", on)
	case "checkUpdate":
		a.checkForUpdate(true)
	case "installUpdate":
		a.installUpdate()
	case "snoozeUpdate":
		a.snoozeUpdate()
	case "register":
		var in struct{ License, Team string }
		if json.Unmarshal([]byte(arg), &in) == nil {
			a.register(in.License, in.Team)
		}
	case "dismissError":
		a.mu.Lock()
		a.lastError = ""
		a.mu.Unlock()
	case "openLogFile":
		open(a.log.path)
	case "openURL":
		// Only the two Cloudflare pages the setup guide links to.
		if arg == "https://www.cloudflare.com/application/terms/" ||
			arg == "https://www.cloudflare.com/application/privacypolicy/" {
			open(arg)
		}
	}
	a.changed()
}

func validSNI(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, ".")
}

// rotatingLog caps sweep.log at 5 MB by rolling it to sweep.log.1. usque logs
// a line per failed client connection, so a PC left signed in for weeks
// otherwise grows it without limit.
type rotatingLog struct {
	path string
	mu   sync.Mutex
	f    *os.File
	size int64
}

const logLimit = 5 << 20

func openRotatingLog(path string) (*rotatingLog, error) {
	l := &rotatingLog{path: path}
	return l, l.reopen()
}

func (l *rotatingLog) reopen() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.f = f
	if fi, err := f.Stat(); err == nil {
		l.size = fi.Size()
	}
	return nil
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size+int64(len(p)) > logLimit {
		l.f.Close()
		_ = os.Remove(l.path + ".1")
		_ = os.Rename(l.path, l.path+".1")
		if err := l.reopen(); err != nil {
			return 0, err
		}
		l.size = 0
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// tail returns up to the last n bytes, starting on a whole line.
func (l *rotatingLog) tail(n int64) string {
	f, err := os.Open(l.path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	off := fi.Size() - n
	if off < 0 {
		off = 0
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && len(buf) == 0 {
		return ""
	}
	s := string(buf)
	if off > 0 {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	return s
}
