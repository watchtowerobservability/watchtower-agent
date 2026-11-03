package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// phpLayout: offsets that differ per branch, from Zend/zend_globals.h and zend_compile.h (NTS,
// LP64). 8.5's were also checked with offsetof against its installed headers.
type phpLayout struct{ curExec, opFilename uint64 }

var phpTables = map[string]phpLayout{
	"8.2": {488, 152}, // security support until 2026-12
	"8.3": {488, 144},
	"8.4": {488, 168},
	"8.5": {512, 168},
}

const (
	phpExecFunc, phpExecPrev         = 24, 48
	phpFuncName, phpFuncScope        = 8, 16
	phpCeName                        = 8
	phpStrInfo, phpStrLen, phpStrVal = 4, 16, 24
	phpTypeString, phpTypeMask       = 6, 0xf
	phpInternal, phpUser, phpEval    = 1, 2, 4
	phpZvalType                      = 8
	phpIsNull, phpIsError            = 1, 15
	phpErrorZval                     = 16
	phpStackPage, phpFiberPage       = 256 * 1024, 16 * 1024 // zend_execute.h, zend_fibers.c
)

var phpVersionRe = regexp.MustCompile(`X-Powered-By: PHP/(\d+\.\d+)\.\d+`)

// phpVersion finds the branch in a binary's read-only data: PHP publishes no version symbol, but
// every SAPI build carries SAPI_PHP_VERSION_HEADER.
func phpVersion(rodata []byte) string {
	i := bytes.Index(rodata, []byte("X-Powered-By: PHP/"))
	if i < 0 {
		return ""
	}
	if m := phpVersionRe.FindSubmatch(rodata[i:min(i+40, len(rodata))]); m != nil {
		return string(m[1])
	}
	return ""
}

// phpWalker reads the one PHP stack of a non-thread-safe process from executor_globals.
type phpWalker struct {
	m     rmem
	eg    uint64
	l     phpLayout
	names map[uint64]string
}

func newPHPWalker(mem memReader, eg uint64, version string) (*phpWalker, error) {
	l, ok := phpTables[version]
	if !ok {
		return nil, fmt.Errorf("PHP %q has no offset table", version)
	}
	return &phpWalker{m: rmem{mem}, eg: eg, l: l, names: map[uint64]string{}}, nil
}

// selfCheck: executor_globals starts with two zvals of known type, and the VM stack page size
// sits right before current_execute_data. All three hold when no script is running.
func (p *phpWalker) selfCheck() error {
	null, e1 := p.m.u8(p.eg + phpZvalType)
	bad, e2 := p.m.u8(p.eg + phpErrorZval + phpZvalType)
	page, e3 := p.m.u64(p.eg + p.l.curExec - 8)
	if err := errors.Join(e1, e2, e3); err != nil {
		return err
	}
	if page == 0 && null == 0 {
		return errNotReady
	}
	if null != phpIsNull || bad != phpIsError || (page != phpStackPage && page != phpFiberPage) {
		return fmt.Errorf("offset table mismatch: executor_globals has zval types %d,%d and stack page %d (debug or patched build?)", null, bad, page)
	}
	return nil
}

func (p *phpWalker) str(s uint64) (string, error) {
	info, err := p.m.u32(s + phpStrInfo)
	if err != nil {
		return "", err
	}
	if info&phpTypeMask != phpTypeString {
		return "", errors.New("not a zend_string")
	}
	n, err := p.m.u64(s + phpStrLen)
	if err != nil {
		return "", err
	}
	if n > rtStackSpan {
		return "", errors.New("implausible string length")
	}
	b := make([]byte, min(n, rtMaxString))
	if err := p.m.ReadAt(s+phpStrVal, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// funcName is `Class::fn (file.php)` for user code and `Class::fn` for internal functions; an
// unnamed user op array is the script body.
func (p *phpWalker) funcName(fn uint64) (string, bool) {
	if n, ok := p.names[fn]; ok {
		return n, true
	}
	typ, err := p.m.u8(fn)
	if err != nil || (typ != phpInternal && typ != phpUser && typ != phpEval) {
		return "", false
	}
	nameAt, e1 := p.m.u64(fn + phpFuncName)
	scope, e2 := p.m.u64(fn + phpFuncScope)
	if e1 != nil || e2 != nil {
		return "", false
	}
	n := "<main>"
	if nameAt != 0 {
		if n, err = p.str(nameAt); err != nil {
			return "", false
		}
	}
	if scope != 0 && nameAt != 0 {
		at, err := p.m.u64(scope + phpCeName)
		if err != nil {
			return "", false
		}
		cls, err := p.str(at)
		if err != nil {
			return "", false
		}
		n = cls + "::" + n
	}
	if typ != phpInternal {
		at, err := p.m.u64(fn + p.l.opFilename)
		if err != nil {
			return "", false
		}
		f, err := p.str(at)
		if err != nil {
			return "", false
		}
		n += " (" + path.Base(f) + ")"
	}
	if !printable(n) {
		return "", false
	}
	n = strings.ReplaceAll(n, ";", ":")
	p.names[fn] = n
	return n, true
}

// Stacks reads the current stack. A frame that fails validation ends it: past a torn frame the
// chain cannot be trusted.
func (p *phpWalker) Stacks() ([]PyStack, error) {
	ex, err := p.m.u64(p.eg + p.l.curExec)
	if err != nil {
		return nil, err
	}
	var fr []string
	for i := 0; ex != 0 && i < rtMaxFrames; i++ {
		fn, err := p.m.u64(ex + phpExecFunc)
		if err != nil {
			break
		}
		if fn != 0 {
			n, ok := p.funcName(fn)
			if !ok {
				break
			}
			fr = append(fr, n)
		}
		if ex, err = p.m.u64(ex + phpExecPrev); err != nil {
			break
		}
	}
	if len(fr) == 0 {
		return nil, nil
	}
	return []PyStack{{Frames: fr}}, nil
}

func (p *phpWalker) resetNames() { p.names = map[uint64]string{} }
