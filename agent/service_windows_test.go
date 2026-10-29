//go:build windows

package main

import (
	"reflect"
	"testing"
)

func TestServiceInstallArgs(t *testing.T) {
	got := serviceArgs(`C:\ProgramData\Watchtower\agent\agent.yaml`)
	want := []string{"-config", `C:\ProgramData\Watchtower\agent\agent.yaml`, "run"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
