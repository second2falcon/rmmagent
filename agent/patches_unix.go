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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	rmm "github.com/amidaware/rmmagent/shared"
)

// Linux patching (#2556). Pending upgrades go through the same API as Windows
// updates: the guid is "package=version" so every version is approved and
// tracked on its own, and the severity drives patch policy auto approval.

type pkgUpgrade struct {
	Pkg, From, To, Severity, Category, Description string
}

func (u pkgUpgrade) guid() string { return u.Pkg + "=" + u.To }

type patcher interface {
	// pending refreshes the package indexes and lists available upgrades
	pending() ([]pkgUpgrade, error)
	// install upgrades the given package=version guids
	install(guids []string) error
	// installedVersions maps installed package names to versions
	installedVersions() map[string]string
}

func (a *Agent) linuxPatcher() patcher {
	switch {
	case aptAvailable():
		return aptPatcher{a}
	case apkAvailable():
		return apkPatcher{a}
	}
	return nil
}

func (a *Agent) GetWinUpdates() {
	p := a.linuxPatcher()
	if p == nil {
		return
	}

	upgrades, err := p.pending()
	if err != nil {
		a.Logger.Errorln(err)
		return
	}

	updates := make([]rmm.WUAPackage, 0, len(upgrades))
	for _, u := range upgrades {
		updates = append(updates, rmm.WUAPackage{
			Title:        fmt.Sprintf("%s %s -> %s", u.Pkg, u.From, u.To),
			Description:  u.Description,
			Categories:   []string{u.Category},
			CategoryIDs:  []string{},
			KBArticleIDs: []string{},
			MoreInfoURLs: []string{},
			UpdateID:     u.guid(),
			Severity:     u.Severity,
		})
	}

	payload := rmm.WinUpdateResult{AgentID: a.AgentID, Updates: updates}
	if _, err := a.rClient.R().SetBody(payload).Post("/api/v3/winupdates/"); err != nil {
		a.Logger.Debugln(err)
	}
}

func (a *Agent) InstallUpdates(guids []string) {
	p := a.linuxPatcher()
	if p == nil {
		return
	}

	upgrades, err := p.pending()
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
		if err := p.install(install); err != nil {
			a.Logger.Errorln(err)
		}

		// report per package, a failed batch may still have installed some
		installed := p.installedVersions()
		for _, guid := range install {
			pkg, ver, _ := strings.Cut(guid, "=")
			result := rmm.WinUpdateInstallResult{
				AgentID:  a.AgentID,
				UpdateID: guid,
				Success:  installed[pkg] == ver,
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

// kernelModulesMissing reports whether the running kernel's modules were
// removed by a kernel upgrade, which is how Alpine signals a pending reboot.
// Hosts without /lib/modules (containers) are never reported.
func kernelModulesMissing() bool {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	entries, err := os.ReadDir("/lib/modules")
	if err != nil || len(entries) == 0 {
		return false
	}
	_, err = os.Stat(filepath.Join("/lib/modules", strings.TrimSpace(string(release))))
	return os.IsNotExist(err)
}
