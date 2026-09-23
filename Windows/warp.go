package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Warp runs usque (Cloudflare WARP over MASQUE) as a child process and exposes
// it as a loopback HTTP proxy. Port of Kit/Sources/SweepVPNKit/WarpController.swift:
// same flags, same log classification, same wedge restart. Windows proxy
// settings speak HTTP (Chromium reads a WinINet "socks=" entry as SOCKS4, which
// usque does not serve), so this runs `http-proxy` where the Mac runs `socks`.
type Warp struct {
	Exe, Config, SNI string
	// Game swaps the loopback proxy for a real TUN device, so traffic that
	// ignores a proxy - games, and the UDP they carry - is tunneled too.
	Game bool
	// FlowTTL retires a healthy MASQUE flow at this age so the ISP's sweep of
	// long-lived TCP flows never reaches it. Empty or "0" disables rotation;
	// it is opt-in because the swap can briefly stall new connections.
	FlowTTL string
	Port             int
	OnState          func(State, string)
	Log              io.Writer

	mu          sync.Mutex
	cmd         *exec.Cmd
	done        chan struct{}
	state       State
	stopped     bool
	exits       []time.Time
	lastRestart time.Time
	lastError   string
	recovery    *time.Timer // armed by a session fault, disarmed by a reconnect
	recoveryGen uint64      // which arming a firing timer belongs to
	streak      int         // consecutive wedge restarts, for the backoff
	streakAt    time.Time

	seq     uint64 // orders state callbacks, which run off the lock
	cbMu    sync.Mutex
	applied uint64
}

type State int

const (
	Stopped State = iota
	Starting
	Running
	Failed
)

func (s State) String() string {
	return [...]string{"Off", "Starting", "Connected", "Failed"}[s]
}

var (
	recoveryGrace = 15 * time.Second
	restartFloor  = 20 * time.Second
	stallTimeout = 30 * time.Second
	respawnDelay = 2 * time.Second
	exitWindow   = 2 * time.Minute
	exitBurst    = 5
)

// Args mirrors WarpController.arguments; the comments there record why each
// flag exists (measured on this ISP, 2026-09-12..14).
func (w *Warp) Args() []string {
	common := []string{"-s", w.SNI, "--http2", "--always-reconnect", "-k", "5s"}

	if !w.Game {
		// socks/http-proxy resolve in-process, so they take the resolver flags.
		args := append([]string{"-c", w.Config, "http-proxy"}, common...)
		args = append(args, "--dns-timeout", "15s", "-d", "1.1.1.1", "-d", "1.0.0.1")
		return append(args, "-b", "127.0.0.1", "-p", strconv.Itoa(w.Port))
	}

	// nativetun has no in-process resolver and rejects those flags outright,
	// which silently killed usque at launch. DNS is set on the interface.

	// -S keeps IPv6 out of the tunnel deliberately: with it on, every new
	// MASQUE session hands out a different public address, so a reconnect
	// changes the player's IP mid-game and the game server drops them
	// (measured 2026-09-18 - v4 held one address across every rotation).
	// --hot-standby goes with rotation and nothing else. A parked standby is
	// swept in the same sweep as the live flow at whatever age it has reached,
	// so as kill recovery it hands the tunnel a corpse and costs a wasted
	// promote cycle (~2s) before the dial that works — measured 2026-09-20,
	// 11 of 26 promotions already dead (docs/measurements-2026-09-20.md).
	// Rotation is the one case that needs a warm session, because there the
	// promotion is planned rather than a response to a kill.
	args := append([]string{"-c", w.Config, "nativetun"}, common...)
	args = append(args, "-S")
	if w.FlowTTL != "" && w.FlowTTL != "0" {
		args = append(args, "--hot-standby", "--flow-ttl", w.FlowTTL)
	}
	return args
}

type logEvent int

const (
	evNone logEvent = iota
	evListening
	evConnected
	evLost
	evError       // the MASQUE session is in trouble: usque owes a reconnect
	evClientError // one client's dial or lookup failed: log it, leave the tunnel alone
)

// sessionFaultPhrases mirrors WarpController.sessionFaultPhrases: the only
// failures usque prints about the session. Anything else containing "failed"
// or "error" belongs to one client and is never followed by a reconnect, so
// arming the wedge deadline on it restarts a healthy tunnel (2026-09-20).
var sessionFaultPhrases = []string{
	"Failed to connect tunnel",
	"Error writing to IP connection",
	"Error reading from IP connection",
	"Failed to read from TUN device",
}

// backoffDelays mirrors StartBackoff.delays: a tunnel that keeps failing to
// heal usually means the path is down, so restarts slow down instead of
// respawning every 20s forever. A streak older than 10 minutes is forgotten.
var backoffDelays = []time.Duration{0, 2 * time.Second, 5 * time.Second, 15 * time.Second,
	30 * time.Second, time.Minute, 2 * time.Minute}

func classify(line string) logEvent {
	switch {
	case strings.Contains(line, "proxy listening on"),
		strings.Contains(line, "Created TUN device"):
		return evListening
	case strings.Contains(line, "Connected to MASQUE server"):
		return evConnected
	case strings.Contains(line, "Tunnel connection lost"):
		return evLost
	}
	for _, p := range sessionFaultPhrases {
		if strings.Contains(line, p) {
			return evError
		}
	}
	l := strings.ToLower(line)
	if strings.Contains(l, "failed") || strings.Contains(l, "error") {
		return evClientError
	}
	return evNone
}

func (w *Warp) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// setState must be called with mu held; the callback runs on its own goroutine.
func (w *Warp) setState(s State, msg string) {
	if s == w.state && s != Failed {
		return
	}
	w.state = s
	cb := w.OnState
	if cb == nil {
		return
	}
	w.seq++
	seq := w.seq
	go func() {
		w.cbMu.Lock()
		defer w.cbMu.Unlock()
		if seq < w.applied {
			return // a newer state already went out
		}
		w.applied = seq
		cb(s, msg)
	}()
}

func (w *Warp) logf(format string, a ...any) {
	if w.Log != nil {
		fmt.Fprintf(w.Log, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", a...)
	}
}

func (w *Warp) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = false
	w.exits = nil
	if w.cmd == nil {
		w.launch()
	}
}

// SetMode switches between the loopback proxy and gaming mode's TUN device.
// Takes effect at the next launch; Args reads these under mu from the respawn
// timer, so they must not be written without it.
func (w *Warp) SetMode(game bool, flowTTL, sni string) {
	w.mu.Lock()
	w.Game, w.FlowTTL = game, flowTTL
	if sni != "" {
		w.SNI = sni
	}
	w.mu.Unlock()
}

func (w *Warp) Stop() {
	w.mu.Lock()
	w.stopped = true
	if w.recovery != nil {
		w.recovery.Stop()
		w.recovery = nil
	}
	c, done := w.cmd, w.done
	w.cmd = nil
	w.setState(Stopped, "")
	w.mu.Unlock()
	kill(c, done)
}

func kill(c *exec.Cmd, done chan struct{}) {
	if c == nil || c.Process == nil {
		return
	}
	_ = c.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// launch must be called with mu held.
func (w *Warp) launch() {
	if _, err := os.Stat(w.Config); err != nil {
		w.setState(Failed, "WARP is not set up yet. Choose \"Set up WARP…\" first.")
		return
	}
	if w.recovery != nil { // belonged to the previous child
		w.recovery.Stop()
		w.recovery = nil
	}
	c := exec.Command(w.Exe, w.Args()...)
	pr, pw := io.Pipe()
	c.Stdout, c.Stderr = pw, pw
	prepare(c)
	if err := c.Start(); err != nil {
		w.setState(Failed, "Could not launch WARP: "+err.Error())
		return
	}
	contain(c)
	done := make(chan struct{})
	w.cmd, w.done = c, done
	w.lastError = ""
	w.setState(Starting, "")
	w.logf("warp starting: sni=%s port=%d pid=%d", w.SNI, w.Port, c.Process.Pid)

	go func() {
		s := bufio.NewScanner(pr)
		for s.Scan() {
			w.ingest(c, s.Text())
		}
	}()
	go func() {
		time.Sleep(stallTimeout)
		w.mu.Lock()
		stalled := w.cmd == c && w.state == Starting
		w.mu.Unlock()
		if stalled {
			w.logf("warp stalled: no listener after %s", stallTimeout)
			w.restart(c, "stalled")
		}
	}()
	go func() {
		err := c.Wait()
		pw.Close()
		close(done)
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.cmd != c || w.stopped {
			return // restart() or Stop() already took over
		}
		w.cmd = nil
		now := time.Now()
		w.exits = append(prune(w.exits, now, exitWindow), now)
		w.logf("warp exited unexpectedly: %v (%s)", err, w.lastError)
		if len(w.exits) >= exitBurst {
			msg := "WARP keeps stopping"
			if w.lastError != "" {
				msg += ": " + w.lastError
			}
			w.setState(Failed, msg)
			return
		}
		// A crash is a disconnect the user did not ask for: come back.
		w.setState(Starting, "")
		time.AfterFunc(respawnDelay, func() {
			w.mu.Lock()
			defer w.mu.Unlock()
			if !w.stopped && w.cmd == nil {
				w.launch()
			}
		})
	}()
}

func prune(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) <= window {
			out = append(out, t)
		}
	}
	return out
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func (w *Warp) ingest(c *exec.Cmd, line string) {
	line = ansi.ReplaceAllString(line, "")
	w.logf("usque: %s", line)
	ev := classify(line)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cmd != c {
		return
	}
	switch ev {
	case evListening:
		w.setState(Running, "")
	case evConnected:
		// usque rebuilt the session by itself: the wedge deadline stands down.
		w.noteRecovered()
	case evLost, evError:
		// A loss is usque saying it is already reconnecting. Both only start
		// the clock; the wedge is the clock running out.
		w.lastError = line
		if w.noteFailure(line, time.Now()) {
			w.logf("warp watching: no reconnect within %s is a wedge", recoveryGrace)
		}
	}
}

// noteFailure (mu held) mirrors WarpController.noteFailure. usque heals its
// own session losses in about a second (masque-closed-pipe.patch +
// --always-reconnect); relaunching the child on the first fault pre-empted
// that and took the proxy port down with it, every sweep (the v1.3.0
// regression). So a fault only arms a deadline, a "Connected to MASQUE
// server" line disarms it, and only an expired deadline restarts usque.
// Returns true if this call armed the deadline.
func (w *Warp) noteFailure(line string, now time.Time) bool {
	if w.cmd == nil || w.recovery != nil || now.Sub(w.lastRestart) < restartFloor {
		return false
	}
	c, grace := w.cmd, recoveryGrace
	w.recoveryGen++
	gen := w.recoveryGen
	w.recovery = time.AfterFunc(grace, func() { w.recoveryExpired(gen, c, line, grace) })
	return true
}

// noteRecovered (mu held): usque reconnected on its own, the common case.
func (w *Warp) noteRecovered() {
	if w.recovery != nil {
		w.recovery.Stop()
		w.recovery = nil
	}
	w.streak = 0
}

func (w *Warp) recoveryExpired(gen uint64, c *exec.Cmd, line string, grace time.Duration) {
	w.mu.Lock()
	if w.recovery == nil || w.recoveryGen != gen || w.cmd != c || w.stopped {
		w.mu.Unlock()
		return // disarmed, replaced, or stopped since it was armed
	}
	w.recovery = nil
	now := time.Now()
	w.lastRestart = now
	if now.Sub(w.streakAt) > 10*time.Minute {
		w.streak = 0
	}
	w.streak++
	w.streakAt = now
	delay := backoffDelays[min(w.streak, len(backoffDelays)-1)]
	w.mu.Unlock()
	w.logf("warp restarting: no reconnect within %s after: %s (waiting %s)", grace, line, delay)
	time.AfterFunc(delay, func() { w.restart(c, line) })
}

func (w *Warp) restart(c *exec.Cmd, why string) {
	w.mu.Lock()
	if w.cmd != c {
		w.mu.Unlock()
		return
	}
	done := w.done
	w.cmd = nil
	w.mu.Unlock()
	kill(c, done)
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped && w.cmd == nil {
		w.launch()
	}
}

// Register mirrors WarpRegistration.register. Only call after the user has
// accepted Cloudflare's terms: --accept-tos accepts them on their behalf.
func Register(exe, config, licenseKey, teamToken string) error {
	licenseKey = strings.TrimSpace(licenseKey)
	if licenseKey != "" && !regexp.MustCompile(`^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$`).MatchString(licenseKey) {
		return errors.New("that license key does not look right; it should look like ab12cd34-ef56gh78-ij90kl12")
	}
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(config); err != nil {
		args := []string{"-c", config, "register", "--accept-tos", "-n", "Sweep VPN"}
		if t := strings.TrimSpace(teamToken); t != "" {
			args = append(args, "--jwt", t)
		}
		if err := runOnce(exe, args, "Registration"); err != nil {
			return err
		}
		if _, err := os.Stat(config); err != nil {
			return errors.New("registration finished but no WARP configuration was saved; try again")
		}
		_ = os.Chmod(config, 0o600)
	}
	if licenseKey != "" {
		return runOnce(exe, []string{"-c", config, "account", "set", licenseKey}, "Setting the license key")
	}
	return nil
}

func runOnce(exe string, args []string, what string) error {
	c := exec.Command(exe, args...)
	prepare(c)
	out, err := c.CombinedOutput()
	if err == nil {
		return nil
	}
	reason := err.Error()
	lines := strings.Split(strings.TrimSpace(ansi.ReplaceAllString(string(out), "")), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		reason = last
	}
	return fmt.Errorf("%s failed: %s. Check your internet connection and any key you entered, then try again", what, reason)
}
