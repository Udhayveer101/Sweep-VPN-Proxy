package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnpackReplacesASameSizedImpostor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usque.exe")
	want := []byte("the embedded binary")

	if err := unpack(path, want, 0o700); err != nil {
		t.Fatal(err)
	}
	// Same length, different bytes: what a size check waved through.
	impostor := []byte("an attacker's binary")[:len(want)]
	if err := os.WriteFile(path, impostor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unpack(path, want, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(want) {
		t.Fatalf("impostor survived: %q", got)
	}
}

func TestUnpackLeavesAnIntactFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wintun.dll")
	want := []byte("intact")
	if err := unpack(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	// Read-only now: a rewrite would fail, as it does for a file in use.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := unpack(path, want, 0o600); err != nil {
		t.Fatalf("rewrote an intact file: %v", err)
	}
}
