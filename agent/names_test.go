package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNamesSkipsDisabledModules(t *testing.T) {
	s := &Supervisor{running: map[string]*runner{
		"host":   {cfg: json.RawMessage(`{"enabled":false}`)},
		"logs":   {cfg: json.RawMessage(`{"enabled":true}`)},
		"docker": {cfg: json.RawMessage(`{}`)},
	}}
	if got, want := s.Names(), []string{"docker", "logs"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
}
