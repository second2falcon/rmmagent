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
	"strconv"
	"strings"
	"time"

	trmm "github.com/wh1te909/trmm-shared"
)

// dpkgQueryFormat: one installed package per line, tab separated
const dpkgQueryFormat = "${db:Status-Status}\t${binary:Package}\t${Version}\t${Maintainer}\t${Installed-Size}\n"

// dpkgInstalledSoftware lists packages on Debian based systems (#2556),
// returns an empty list where dpkg-query is not available
func dpkgInstalledSoftware() []trmm.WinSoftwareList {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", dpkgQueryFormat).Output()
	if err != nil {
		return []trmm.WinSoftwareList{}
	}

	ret := parseDpkgQuery(string(out))
	for i := range ret {
		ret[i].InstallDate = dpkgInstallDate(ret[i].Name)
	}
	return ret
}

func parseDpkgQuery(out string) []trmm.WinSoftwareList {
	ret := make([]trmm.WinSoftwareList, 0)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		// skip removed packages that only have config files left
		if len(f) != 5 || f[0] != "installed" {
			continue
		}

		size := ""
		if kb, err := strconv.ParseUint(f[4], 10, 64); err == nil {
			size = ByteCountSI(kb * 1024)
		}

		ret = append(ret, trmm.WinSoftwareList{
			Name:      CleanString(f[1]),
			Version:   CleanString(f[2]),
			Publisher: CleanString(f[3]),
			Size:      size,
			Source:    "dpkg",
		})
	}
	return ret
}

// dpkg keeps no install date, the file list is written on install/upgrade
func dpkgInstallDate(pkg string) string {
	fi, err := os.Stat(fmt.Sprintf("/var/lib/dpkg/info/%s.list", pkg))
	if err != nil {
		// multiarch packages are listed as name:arch, the file may not be
		name, _, _ := strings.Cut(pkg, ":")
		if fi, err = os.Stat(fmt.Sprintf("/var/lib/dpkg/info/%s.list", name)); err != nil {
			return ""
		}
	}
	t := fi.ModTime()
	return fmt.Sprintf("%02d-%d-%02d", t.Year(), t.Month(), t.Day())
}
