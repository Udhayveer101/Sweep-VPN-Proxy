package main

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestSystemProxyRoundTrip(t *testing.T) {
	inet, err := openKey(inetKey)
	if err != nil {
		t.Fatal(err)
	}
	defer inet.Close()
	_ = inet.SetDWordValue("ProxyEnable", 1)
	_ = inet.SetStringValue("ProxyServer", "corp.example:8080")
	_ = inet.SetStringValue("ProxyOverride", "*.corp")

	if err := SetSystemProxy(1080); err != nil {
		t.Fatal(err)
	}
	if err := SetSystemProxy(1080); err != nil { // twice must not overwrite the saved copy
		t.Fatal(err)
	}
	if !SystemProxyIsOurs(1080) {
		t.Fatal("proxy not pointed at us")
	}
	if err := RestoreSystemProxy(); err != nil {
		t.Fatal(err)
	}
	server, _, _ := inet.GetStringValue("ProxyServer")
	override, _, _ := inet.GetStringValue("ProxyOverride")
	enable, _, _ := inet.GetIntegerValue("ProxyEnable")
	if server != "corp.example:8080" || override != "*.corp" || enable != 1 {
		t.Fatalf("not restored: %q %q %d", server, override, enable)
	}
	if err := RestoreSystemProxy(); err != nil { // no-op when not ours
		t.Fatal(err)
	}
	if s, _, _ := inet.GetStringValue("ProxyServer"); s != "corp.example:8080" {
		t.Fatalf("second restore changed settings: %q", s)
	}

	_ = inet.SetDWordValue("ProxyEnable", 0)
	_ = inet.DeleteValue("ProxyServer")
	_ = inet.DeleteValue("ProxyOverride")
	_ = SetSystemProxy(1080)
	_ = RestoreSystemProxy()
	if _, _, err := inet.GetStringValue("ProxyServer"); err != registry.ErrNotExist {
		t.Fatalf("ProxyServer should be gone again, err=%v", err)
	}
}

func TestIconIsValidICO(t *testing.T) {
	b := icon(1, 2, 3)
	if len(b) != 22+40+32*32*4+4*32 || b[2] != 1 {
		t.Fatalf("bad icon, %d bytes", len(b))
	}
}
