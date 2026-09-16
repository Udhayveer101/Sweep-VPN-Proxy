//go:build !windows

package main

import "os/exec"

func prepare(*exec.Cmd) {}
func contain(*exec.Cmd) {}
