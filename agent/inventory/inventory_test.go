package inventory

import (
	"strings"
	"testing"
	"time"
)

func TestParseDpkgKeepsOnlyInstalled(t *testing.T) {
	const status = `Package: bash
Status: install ok installed
Priority: required
Version: 5.2.15-2
Description: GNU Bourne Again SHell
 multi-line description: with a colon

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: zlib1g
Status: install ok installed
Version: 1:1.2.13.dfsg-1
`
	got := ParseDpkg(strings.NewReader(status))
	if len(got) != 2 || got[0] != (Package{"bash", "5.2.15-2", "dpkg"}) || got[1].Version != "1:1.2.13.dfsg-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseApkAndRpm(t *testing.T) {
	apk := ParseApk(strings.NewReader("C:Q1abc\nP:musl\nV:1.2.4-r2\nA:x86_64\n\nP:busybox\nV:1.36.1-r5\n"))
	if len(apk) != 2 || apk[1] != (Package{"busybox", "1.36.1-r5", "apk"}) {
		t.Fatalf("apk %+v", apk)
	}
	rpm := ParseRpm("openssl\t3.0.7-27.el9\nkernel\t5.14.0-427.el9\n\n")
	if len(rpm) != 2 || rpm[0] != (Package{"openssl", "3.0.7-27.el9", "rpm"}) {
		t.Fatalf("rpm %+v", rpm)
	}
}

type logRec struct{ attrs []map[string]string }

func (l *logRec) Log(_, _ string, a map[string]string, _ time.Time) { l.attrs = append(l.attrs, a) }

func TestReportWritesSystemThenPackages(t *testing.T) {
	var l logRec
	Report(&l, map[string]string{"os.kernel": "6.8.0", "os.description": "ubuntu 24.04"}, []Package{{"bash", "5.2", "dpkg"}}, time.Now())
	if len(l.attrs) != 2 || l.attrs[0]["event.name"] != "host.system" || l.attrs[0]["os.kernel"] != "6.8.0" ||
		l.attrs[1]["event.name"] != "host.package" || l.attrs[1]["package.name"] != "bash" {
		t.Fatalf("%+v", l.attrs)
	}
}
