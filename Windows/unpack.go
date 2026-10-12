package main

import (
	"bytes"
	"os"
)

// unpack makes path hold exactly want, rewriting it when it does not.
//
// The embedded usque.exe and wintun.dll land in %LOCALAPPDATA%, which every
// program the user runs can write, and gaming mode runs them with
// administrator rights. The check used to be the file's size alone, so a
// same-sized replacement was kept and then run elevated. Compare the bytes.
//
// ponytail: the file can still be swapped between this check and the launch.
// Closing that needs the elevated copy in a folder only administrators can
// write (ProgramData with an admin-only ACL); do that when there is a Windows
// machine to test the ACL on.
func unpack(path string, want []byte, mode os.FileMode) error {
	if got, err := os.ReadFile(path); err == nil && bytes.Equal(got, want) {
		return nil
	}
	return os.WriteFile(path, want, mode)
}
