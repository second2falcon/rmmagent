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

	rmm "github.com/amidaware/rmmagent/shared"
)

// Debian based patching (#2556). Pending upgrades go through the same API as
// Windows updates: the guid is "package=version" so every version is approved
// and tracked on its own, and security updates map to the Critical severity.

type aptUpgrade struct {
	Pkg, From, To, Origin string
}

func (u aptUpgrade) guid() string { return u.Pkg + "=" + u.To }

func (u aptUpgrade) security() bool {
	return strings.Contains(strings.ToLower(u.Origin), "security")
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

func (a *Agent) GetWinUpdates() {
	if !aptAvailable() {
		return
	}

	upgrades, err := a.aptPendingUpgrades()
	if err != nil {
		a.Logger.Errorln(err)
		return
	}

	updates := make([]rmm.WUAPackage, 0, len(upgrades))
	for _, u := range upgrades {
		severity, category := "", "Updates"
		if u.security() {
			severity, category = "Critical", "Security Updates"
		}
		updates = append(updates, rmm.WUAPackage{
			Title:        fmt.Sprintf("%s %s -> %s", u.Pkg, u.From, u.To),
			Description:  u.Origin,
			Categories:   []string{category},
			CategoryIDs:  []string{},
			KBArticleIDs: []string{},
			MoreInfoURLs: []string{},
			UpdateID:     u.guid(),
			Severity:     severity,
		})
	}

	payload := rmm.WinUpdateResult{AgentID: a.AgentID, Updates: updates}
	if _, err := a.rClient.R().SetBody(payload).Post("/api/v3/winupdates/"); err != nil {
		a.Logger.Debugln(err)
	}
}

func (a *Agent) InstallUpdates(guids []string) {
	if !aptAvailable() {
		return
	}

	upgrades, err := a.aptPendingUpgrades()
	if err != nil {
		a.Logger.Errorln(err)
		return
	}
	candidates := make(map[string]bool, len(upgrades))
	for _, u := range upgrades {
		candidates[u.guid()] = true
	}

	// a newer version replaced the approved one since the scan
	install := make([]string, 0, len(guids))
	for _, guid := range guids {
		if candidates[guid] {
			install = append(install, guid)
			continue
		}
		superseded := rmm.SupersededUpdate{AgentID: a.AgentID, UpdateID: guid}
		a.rClient.R().SetBody(superseded).Post("/api/v3/superseded/")
	}

	if len(install) > 0 {
		args := append([]string{
			"-y", "-q",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"install", "--only-upgrade",
		}, install...)
		if out, err := aptGet(time.Hour, args...); err != nil {
			a.Logger.Errorln("apt-get install:", err, out)
		}

		// report per package, a failed batch may still have installed some
		for _, guid := range install {
			pkg, ver, _ := strings.Cut(guid, "=")
			out, _ := exec.Command("dpkg-query", "-W", "-f", "${Version}", pkg).Output()
			result := rmm.WinUpdateInstallResult{
				AgentID:  a.AgentID,
				UpdateID: guid,
				Success:  strings.TrimSpace(string(out)) == ver,
			}
			a.rClient.R().SetBody(result).Patch("/api/v3/winupdates/")
		}
	}

	needsReboot, err := a.SystemRebootRequired()
	if err != nil {
		a.Logger.Errorln(err)
	}
	rebootPayload := rmm.AgentNeedsReboot{AgentID: a.AgentID, NeedsReboot: needsReboot}
	if _, err := a.rClient.R().SetBody(rebootPayload).Put("/api/v3/winupdates/"); err != nil {
		a.Logger.Debugln("NeedsReboot:", err)
	}
}
