//go:build !windows
// +build !windows

package agent

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitApkNameVersion(t *testing.T) {
	cases := map[string][2]string{
		"busybox-1.37.0-r8":          {"busybox", "1.37.0-r8"},
		"font-adobe-100dpi-1.0.4-r2": {"font-adobe-100dpi", "1.0.4-r2"},
		"libstdc++-14.2.0-r4":        {"libstdc++", "14.2.0-r4"},
		"lua5.4-5.4.7-r0":            {"lua5.4", "5.4.7-r0"},
		"py3-pip-24.3.1-r0":          {"py3-pip", "24.3.1-r0"},
		"noversion":                  {"", ""},
	}
	for in, want := range cases {
		name, ver := splitApkNameVersion(in)
		if name != want[0] || ver != want[1] {
			t.Errorf("splitApkNameVersion(%q) = %q, %q, want %q", in, name, ver, want)
		}
	}
}

func TestParseApkUpgradable(t *testing.T) {
	out := `alpine-release-3.23.6-r0 aarch64 {alpine-base} (MIT) [upgradable from: alpine-release-3.23.0-r0]
busybox-1.37.0-r30 aarch64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.37.0-r29]
libcrypto3-3.5.4-r0 x86_64 {openssl} (Apache-2.0) [upgradable from: libcrypto3-3.5.1-r0]
zlib-1.3.2-r1 x86_64 {zlib} (Zlib) [installed]
`
	got := parseApkUpgradable(out)
	want := []apkUpgradable{
		{Pkg: "alpine-release", Version: "3.23.6-r0", Origin: "alpine-base", From: "3.23.0-r0"},
		{Pkg: "busybox", Version: "1.37.0-r30", Origin: "busybox", From: "1.37.0-r29"},
		{Pkg: "libcrypto3", Version: "3.5.4-r0", Origin: "openssl", From: "3.5.1-r0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseApkUpgradable() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestApkSecdbURLs(t *testing.T) {
	repos := `https://dl-cdn.alpinelinux.org/alpine/v3.22/main
https://dl-cdn.alpinelinux.org/alpine/v3.22/community/
#https://dl-cdn.alpinelinux.org/alpine/edge/testing
@edge https://dl-cdn.alpinelinux.org/alpine/edge/main
http://mirror.example.com/alpine/v3.22/main
https://packages.example.com/custom
`
	want := []string{
		"https://secdb.alpinelinux.org/v3.22/main.json",
		"https://secdb.alpinelinux.org/v3.22/community.json",
	}
	if got := apkSecdbURLs(repos); !reflect.DeepEqual(got, want) {
		t.Errorf("apkSecdbURLs() = %v, want %v", got, want)
	}
}

func TestApkSecurityClassification(t *testing.T) {
	secdb := `{"packages":[
	{"pkg":{"name":"openssl","secfixes":{"3.5.4-r0":["CVE-2025-9230"],"3.1.4-r1":["CVE-2023-5678"],"0":["CVE-2016-0000"]}}},
	{"pkg":{"name":"busybox","secfixes":{"1.36.1-r29":["CVE-2023-42366"]}}}
]}`
	fixes := map[string][]string{}
	if err := parseApkSecdb([]byte(secdb), fixes); err != nil {
		t.Fatal(err)
	}
	if len(fixes["openssl"]) != 2 {
		t.Fatalf("expected 2 openssl fixes without the 0 entry, got %v", fixes["openssl"])
	}

	// plain string compare is enough for these fixed width test versions
	less := func(a, b string) bool { return strings.Compare(a, b) < 0 }
	if !fixesSecurity(fixes["openssl"], "3.5.1-r0", "3.5.4-r0", less) {
		t.Error("openssl 3.5.1 -> 3.5.4 includes CVE-2025-9230")
	}
	if fixesSecurity(fixes["openssl"], "3.5.4-r0", "3.5.5-r0", less) {
		t.Error("openssl 3.5.4 -> 3.5.5 has no listed fix")
	}
	if fixesSecurity(fixes["busybox"], "1.37.0-r29", "1.37.0-r30", less) {
		t.Error("busybox fix predates the installed version")
	}
}
