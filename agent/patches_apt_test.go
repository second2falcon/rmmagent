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
		guid string
		from string
	}{
		{"libssl3=3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.14"},
		{"openssl=3.0.15-1~deb12u1", "3.0.11-1~deb12u1"},
		{"tzdata=2024b-0+deb12u1", "2024a-0+deb12u1"},
	}
	for i, w := range want {
		if got[i].guid() != w.guid || got[i].From != w.from {
			t.Errorf("upgrade %d = %+v (guid %s), want %+v", i, got[i], got[i].guid(), w)
		}
	}
}

func TestAptClassify(t *testing.T) {
	cases := map[string]string{
		"Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security": "Critical",
		"Debian:12.8/stable, Debian-Security:12/stable-security":  "Critical",
		"Debian:12.8/stable":                                       "Important",
		"Debian:12.8/stable-updates":                               "Important",
		"Ubuntu:24.04/noble-updates":                               "Important",
		"Debian Backports:bookworm-backports/bookworm-backports":   "Moderate",
		"Debian:bookworm-backports/bookworm-backports":             "Moderate",
		"Ubuntu:24.04/noble-backports":                             "Moderate",
		"Ubuntu:24.04/noble-backports, Ubuntu:24.04/noble-updates": "Important",
		"Docker:/noble":                                            "Low",
		"LP-PPA-ondrej-php:24.04/noble":                            "Low",
		"Proxmox:bookworm/stable":                                  "Important",
		"localhost":                                                "",
		"":                                                         "",
	}
	for origin, want := range cases {
		if got, _ := (aptUpgrade{Origin: origin}).classify(); got != want {
			t.Errorf("classify(%q) = %q, want %q", origin, got, want)
		}
	}
}
