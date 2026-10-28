//go:build !windows
// +build !windows

package agent

import "testing"

func TestParseAptSimulate(t *testing.T) {
	out := `Reading package lists...
Calculating upgrade...
The following packages will be upgraded:
  libssl3 openssl
Inst libssl3 [3.0.2-0ubuntu1.14] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])
Inst openssl [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian:12.8/stable, Debian-Security:12/stable-security [amd64]) []
Inst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.8/stable-updates [all])
Inst linux-image-6.1.0-28-amd64 (6.1.119-1 Debian-Security:12/stable-security [amd64])
Conf libssl3 (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])
`
	got := parseAptSimulate(out)
	if len(got) != 3 {
		t.Fatalf("expected 3 upgrades, got %d: %+v", len(got), got)
	}

	want := []struct {
		guid     string
		from     string
		security bool
	}{
		{"libssl3=3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.14", true},
		{"openssl=3.0.15-1~deb12u1", "3.0.11-1~deb12u1", true},
		{"tzdata=2024b-0+deb12u1", "2024a-0+deb12u1", false},
	}
	for i, w := range want {
		if got[i].guid() != w.guid || got[i].From != w.from || got[i].security() != w.security {
			t.Errorf("upgrade %d = %+v (guid %s), want %+v", i, got[i], got[i].guid(), w)
		}
	}
}
