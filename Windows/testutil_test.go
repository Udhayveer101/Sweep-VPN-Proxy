package main

import (
	"os/exec"
	"strconv"
	"testing"
	"time"
)

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func dummyCmd() *exec.Cmd { return exec.Command("x") }
func itoa(i int) string   { return strconv.Itoa(i) }

func waitFor(t *testing.T, states chan State, want State) {
	t.Helper()
	deadline := time.After(60 * time.Second)
	for {
		select {
		case s := <-states:
			if s == want {
				return
			}
			if s == Failed {
				t.Fatalf("failed while waiting for %v", want)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %v", want)
		}
	}
}
