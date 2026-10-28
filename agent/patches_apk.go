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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// Alpine patching (#2556), see patches_unix.go for the shared flow.
// Upgrades that fix a CVE according to the Alpine security database (secdb)
// are Critical, all other upgrades from the configured repos are Important.

const apkSecdbURL = "https://secdb.alpinelinux.org"

func apkAvailable() bool {
	_, err := exec.LookPath("apk")
	return err == nil
}

func apkCmd(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "apk", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("apk %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out), nil
}

type apkUpgradable struct {
	Pkg, Version, Origin, From string
}

var apkRevision = regexp.MustCompile(`-r\d+$`)

// splitApkNameVersion splits "font-adobe-100dpi-1.0.4-r2" into name and
// version. Names may contain "-digit", so the version is the last "-digit"
// part before the optional -rN revision.
func splitApkNameVersion(s string) (name, version string) {
	base := s
	if loc := apkRevision.FindStringIndex(s); loc != nil {
		base = s[:loc[0]]
	}
	i := strings.LastIndex(base, "-")
	if i <= 0 || i+1 >= len(base) || base[i+1] < '0' || base[i+1] > '9' {
		return "", ""
	}
	return s[:i], s[i+1:]
}

// parseApkUpgradable reads apk list --upgradable output, e.g.
// busybox-1.37.0-r30 x86_64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.37.0-r29]
func parseApkUpgradable(out string) []apkUpgradable {
	const marker = "[upgradable from: "
	ret := make([]apkUpgradable, 0)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		at := strings.LastIndex(line, marker)
		if len(fields) == 0 || at == -1 {
			continue
		}
		name, version := splitApkNameVersion(fields[0])
		_, from := splitApkNameVersion(strings.TrimSuffix(strings.TrimSpace(line[at+len(marker):]), "]"))
		if name == "" || from == "" {
			continue
		}

		origin := name
		if i := strings.Index(line, "{"); i != -1 {
			if j := strings.Index(line[i:], "}"); j > 1 {
				origin = line[i+1 : i+j]
			}
		}
		ret = append(ret, apkUpgradable{Pkg: name, Version: version, Origin: origin, From: from})
	}
	return ret
}

var apkBranch = regexp.MustCompile(`^(v\d+\.\d+|edge)$`)

// apkSecdbURLs maps the untagged main/community repos in /etc/apk/repositories
// to their secdb files, e.g. .../alpine/v3.22/main -> secdb .../v3.22/main.json
func apkSecdbURLs(repositories string) []string {
	ret := make([]string, 0)
	seen := make(map[string]bool)
	for _, line := range strings.Split(repositories, "\n") {
		line = strings.TrimSpace(line)
		// skip comments and tagged repos (@testing ...), those are opt in
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		parts := strings.Split(strings.TrimRight(line, "/"), "/")
		for i := 0; i < len(parts)-1; i++ {
			repo := parts[i+1]
			if apkBranch.MatchString(parts[i]) && (repo == "main" || repo == "community") {
				url := fmt.Sprintf("%s/%s/%s.json", apkSecdbURL, parts[i], repo)
				if !seen[url] {
					seen[url] = true
					ret = append(ret, url)
				}
			}
		}
	}
	return ret
}

// parseApkSecdb returns the fixed versions per source package
func parseApkSecdb(data []byte, fixes map[string][]string) error {
	var db struct {
		Packages []struct {
			Pkg struct {
				Name     string                     `json:"name"`
				Secfixes map[string]json.RawMessage `json:"secfixes"`
			} `json:"pkg"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &db); err != nil {
		return err
	}
	for _, p := range db.Packages {
		for ver := range p.Pkg.Secfixes {
			// "0" lists CVEs that never affected the alpine package
			if ver != "0" {
				fixes[p.Pkg.Name] = append(fixes[p.Pkg.Name], ver)
			}
		}
	}
	return nil
}

// fixesSecurity reports whether upgrading from -> to includes a security fix
func fixesSecurity(fixed []string, from, to string, less func(a, b string) bool) bool {
	for _, f := range fixed {
		if less(from, f) && !less(to, f) {
			return true
		}
	}
	return false
}

func apkVersionLess(a, b string) bool {
	out, err := apkCmd(10*time.Second, "version", "-t", a, b)
	return err == nil && strings.TrimSpace(out) == "<"
}

// apkPatcher implements patcher for Alpine
type apkPatcher struct{ a *Agent }

func (p apkPatcher) secfixes() map[string][]string {
	repos, err := os.ReadFile("/etc/apk/repositories")
	if err != nil {
		return nil
	}

	client := resty.New()
	client.SetTimeout(2 * time.Minute)
	if len(p.a.Proxy) > 0 {
		client.SetProxy(p.a.Proxy)
	}

	fixes := make(map[string][]string)
	for _, url := range apkSecdbURLs(string(repos)) {
		r, err := client.R().Get(url)
		if err != nil || r.IsError() {
			p.a.Logger.Debugln("apk secdb:", url, err, r.StatusCode())
			continue
		}
		if err := parseApkSecdb(r.Body(), fixes); err != nil {
			p.a.Logger.Debugln("apk secdb:", url, err)
		}
	}
	return fixes
}

func (p apkPatcher) pending() ([]pkgUpgrade, error) {
	if _, err := apkCmd(10*time.Minute, "update", "-q"); err != nil {
		p.a.Logger.Debugln(err)
	}

	out, err := apkCmd(5*time.Minute, "list", "--upgradable")
	if err != nil {
		return nil, err
	}
	upgradable := parseApkUpgradable(out)

	var fixes map[string][]string
	if len(upgradable) > 0 {
		fixes = p.secfixes()
	}

	ret := make([]pkgUpgrade, 0, len(upgradable))
	for _, u := range upgradable {
		severity, category := "Important", "Updates"
		if fixesSecurity(fixes[u.Origin], u.From, u.Version, apkVersionLess) {
			severity, category = "Critical", "Security Updates"
		}
		ret = append(ret, pkgUpgrade{
			Pkg: u.Pkg, From: u.From, To: u.Version,
			Severity: severity, Category: category, Description: "origin: " + u.Origin,
		})
	}
	return ret, nil
}

// install upgrades the named packages, unlike apk add this does not pin them
// in /etc/apk/world. apk cannot target a version, pending() already checked
// that the approved version is the one apk will install.
func (p apkPatcher) install(guids []string) error {
	args := []string{"upgrade", "-q", "--no-progress"}
	for _, guid := range guids {
		pkg, _, _ := strings.Cut(guid, "=")
		args = append(args, pkg)
	}
	_, err := apkCmd(time.Hour, args...)
	return err
}

func (p apkPatcher) installedVersions() map[string]string {
	ret := make(map[string]string)
	for _, sw := range apkInstalledSoftware() {
		ret[sw.Name] = sw.Version
	}
	return ret
}
