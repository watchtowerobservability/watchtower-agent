//go:build windows

package logs

import (
	"context"
	"log/slog"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Windows Event Log API (wevtapi.dll), loaded lazily; no cgo.
var (
	wevtapi          = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = wevtapi.NewProc("EvtSubscribe")
	procEvtNext      = wevtapi.NewProc("EvtNext")
	procEvtRender    = wevtapi.NewProc("EvtRender")
	procEvtClose     = wevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
	errorInsufficientBuffer    = 122
	errorNoMoreItems           = 259
	batch                      = 32
)

// RunWinEvents subscribes to the channels' future events and forwards each as a log record.
//
// shortcut: no bookmark is kept, so events written while the agent is down are not replayed;
// upgrade by persisting an EvtCreateBookmark XML in the state dir.
func RunWinEvents(ctx context.Context, c WinEvent, out sink.Sink) error {
	chans := c.Channels
	if len(chans) == 0 {
		chans = []string{"System", "Application"}
	}
	query := c.Query
	if query == "" {
		query = "*"
	}
	signal, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(signal)
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return err
	}
	var subs []uintptr
	defer func() {
		for _, h := range subs {
			procEvtClose.Call(h)
		}
	}()
	for _, ch := range chans {
		cp, err := windows.UTF16PtrFromString(ch)
		if err != nil {
			return err
		}
		h, _, e := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(cp)), uintptr(unsafe.Pointer(q)),
			0, 0, 0, evtSubscribeToFutureEvents)
		if h == 0 {
			slog.Warn("cannot subscribe to event channel", "channel", ch, "error", e)
			continue
		}
		subs = append(subs, h)
	}
	for ctx.Err() == nil {
		// auto-reset event: wake on new events or every second to check ctx
		_, _ = windows.WaitForSingleObject(signal, 1000)
		for _, h := range subs {
			drain(h, out)
		}
	}
	return nil
}

func drain(sub uintptr, out sink.Sink) {
	for {
		var evs [batch]uintptr
		var n uint32
		ok, _, err := procEvtNext.Call(sub, batch, uintptr(unsafe.Pointer(&evs[0])), 0, 0, uintptr(unsafe.Pointer(&n)))
		if ok == 0 {
			if err != windows.Errno(errorNoMoreItems) {
				slog.Debug("EvtNext", "error", err)
			}
			return
		}
		for _, ev := range evs[:n] {
			if x, err := render(ev); err == nil {
				if r, err := ParseEventXML(x); err == nil {
					r.send(out, nil)
				}
			}
			procEvtClose.Call(ev)
		}
	}
}

func render(ev uintptr) (string, error) {
	var used, props uint32
	buf := make([]uint16, 4096)
	for range 2 {
		ok, _, err := procEvtRender.Call(0, ev, evtRenderEventXML, uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if ok != 0 {
			return windows.UTF16ToString(buf), nil
		}
		if err != windows.Errno(errorInsufficientBuffer) {
			return "", err
		}
		buf = make([]uint16, used/2+1)
	}
	return "", windows.Errno(errorInsufficientBuffer)
}
