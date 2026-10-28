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
	"os"
	"strconv"
	"strings"

	trmm "github.com/wh1te909/trmm-shared"
)

const apkInstalledDB = "/lib/apk/db/installed"

// apkInstalledSoftware lists packages on Alpine from the apk database (#2556),
// returns an empty list where it does not exist
func apkInstalledSoftware() []trmm.WinSoftwareList {
	data, err := os.ReadFile(apkInstalledDB)
	if err != nil {
		return []trmm.WinSoftwareList{}
	}
	return parseApkInstalledDB(string(data))
}

// The database is blocks of "X:value" lines separated by a blank line,
// P is the name, V the version, m the maintainer and I the installed size.
func parseApkInstalledDB(db string) []trmm.WinSoftwareList {
	ret := make([]trmm.WinSoftwareList, 0)
	var cur trmm.WinSoftwareList

	flush := func() {
		if cur.Name != "" {
			cur.Source = "apk"
			ret = append(ret, cur)
		}
		cur = trmm.WinSoftwareList{}
	}

	for _, line := range strings.Split(db, "\n") {
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "P":
			cur.Name = CleanString(value)
		case "V":
			cur.Version = CleanString(value)
		case "m":
			cur.Publisher = CleanString(value)
		case "I":
			if size, err := strconv.ParseUint(value, 10, 64); err == nil {
				cur.Size = ByteCountSI(size)
			}
		}
	}
	flush()
	return ret
}
