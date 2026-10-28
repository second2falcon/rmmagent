//go:build !windows
// +build !windows

package agent

import "testing"

func TestParseApkInstalledDB(t *testing.T) {
	db := `C:Q1abc=
P:busybox
V:1.37.0-r8
A:x86_64
S:509468
I:1007616
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Sören Tempel <soeren+alpine@soeren-tempel.net>
t:1734542389
F:bin
R:busybox

C:Q1def=
P:font-adobe-100dpi
V:1.0.4-r2
A:noarch
I:abc
o:font-adobe-100dpi
`
	got := parseApkInstalledDB(db)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(got), got)
	}
	if got[0].Name != "busybox" || got[0].Version != "1.37.0-r8" || got[0].Size == "" || got[0].Source != "apk" {
		t.Errorf("bad busybox: %+v", got[0])
	}
	if got[1].Name != "font-adobe-100dpi" || got[1].Version != "1.0.4-r2" || got[1].Size != "" {
		t.Errorf("bad font package: %+v", got[1])
	}
}
