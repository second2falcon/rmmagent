//go:build !windows
// +build !windows

/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the “License”).
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Debian based patching (#2556), see patches_unix.go for the shared flow.
// The severity comes from the repository, see classify.

type aptUpgrade struct {
	Pkg, From, To, Origin string
}

func (u aptUpgrade) guid() string { return u.Pkg + "=" + u.To }

// origins of Debian and derived distributions, anything else is third party
var aptDistroOrigins = map[string]bool{
	"debian": true, "debian-security": true, "debian backports": true, "ubuntu": true, "raspbian": true,
	"raspberry pi foundation": true, "devuan": true, "linuxmint": true,
	"kali": true, "proxmox": true,
}

// classify maps the repository of an upgrade to a patch policy severity:
// security Critical, distro updates Important, backports Moderate, third
// party repos Low, unrecognised Other. With several repos the highest wins.
func (u aptUpgrade) classify() (severity, category string) {
	type level struct {
		rank               int
		severity, category string
	}
	best := level{0, "", "Other"}
	// e.g. "Debian:12.8/stable, Debian-Security:12/stable-security"
	for _, entry := range strings.Split(u.Origin, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		origin, rest, ok := strings.Cut(entry, ":")
		slash := strings.LastIndex(rest, "/")
		if !ok || slash == -1 {
			continue
		}
		archive := rest[slash+1:]

		l := level{1, "Low", "Third-party"}
		switch {
		case strings.Contains(archive, "security"):
			l = level{4, "Critical", "Security Updates"}
		case aptDistroOrigins[origin] && strings.HasSuffix(archive, "-backports"):
			l = level{2, "Moderate", "Backports"}
		case aptDistroOrigins[origin]:
			l = level{3, "Important", "Updates"}
		}
		if l.rank > best.rank {
			best = l
		}
	}
	return best.severity, best.category
}

// e.g. Inst openssl [3.0.2-0ubuntu1.14] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])
// new packages pulled in as dependencies have no [old version] and are skipped
var aptInstLine = regexp.MustCompile(`^Inst (\S+) \[([^\]]+)\] \((\S+) (.*?)(?: \[[^\]]*\])?\)`)

func parseAptSimulate(out string) []aptUpgrade {
	ret := make([]aptUpgrade, 0)
	for _, line := range strings.Split(out, "\n") {
		if m := aptInstLine.FindStringSubmatch(line); m != nil {
			ret = append(ret, aptUpgrade{Pkg: m[1], From: m[2], To: m[3], Origin: m[4]})
		}
	}
	return ret
}

func aptGet(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func aptAvailable() bool {
	_, err := exec.LookPath("apt-get")
	return err == nil
}

// aptPendingUpgrades refreshes the package lists and simulates a full upgrade
func (a *Agent) aptPendingUpgrades() ([]aptUpgrade, error) {
	if out, err := aptGet(10*time.Minute, "update", "-q"); err != nil {
		a.Logger.Debugln("apt-get update:", err, out)
	}

	out, err := aptGet(5*time.Minute, "-s", "-q", "dist-upgrade")
	if err != nil {
		return nil, fmt.Errorf("apt-get -s dist-upgrade: %w: %s", err, out)
	}
	return parseAptSimulate(out), nil
}

// aptPatcher implements patcher for Debian based systems
type aptPatcher struct{ a *Agent }

func (p aptPatcher) pending() ([]pkgUpgrade, error) {
	upgrades, err := p.a.aptPendingUpgrades()
	if err != nil {
		return nil, err
	}
	ret := make([]pkgUpgrade, 0, len(upgrades))
	for _, u := range upgrades {
		severity, category := u.classify()
		ret = append(ret, pkgUpgrade{
			Pkg: u.Pkg, From: u.From, To: u.To,
			Severity: severity, Category: category, Description: u.Origin,
		})
	}
	return ret, nil
}

// install pins the approved versions (package=version)
func (p aptPatcher) install(guids []string) error {
	args := append([]string{
		"-y", "-q",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"install", "--only-upgrade",
	}, guids...)
	if out, err := aptGet(time.Hour, args...); err != nil {
		return fmt.Errorf("apt-get install: %w: %s", err, out)
	}
	return nil
}

func (p aptPatcher) installedVersions() map[string]string {
	out, _ := exec.Command("dpkg-query", "-W", "-f", "${Package}\t${Version}\n").Output()
	ret := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if pkg, ver, ok := strings.Cut(line, "\t"); ok {
			ret[pkg] = ver
		}
	}
	return ret
}
