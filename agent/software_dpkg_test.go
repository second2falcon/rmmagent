//go:build !windows
// +build !windows

package agent

import "testing"

func TestParseDpkgQuery(t *testing.T) {
	out := "installed\tbash\t5.2.15-2+b7\tMatthias Klose <doko@debian.org>\t7148\n" +
		"config-files\told-pkg\t1.0\tNobody <n@x>\t10\n" +
		"installed\tlibc6:amd64\t2.36-9\tGNU Libc Maintainers <x@y>\t\n" +
		"garbage line\n"

	got := parseDpkgQuery(out)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(got), got)
	}
	if got[0].Name != "bash" || got[0].Version != "5.2.15-2+b7" || got[0].Size == "" {
		t.Errorf("bad first package: %+v", got[0])
	}
	if got[1].Name != "libc6:amd64" || got[1].Size != "" {
		t.Errorf("bad multiarch package: %+v", got[1])
	}
}
