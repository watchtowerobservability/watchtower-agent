package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Identity is persisted at <state_dir>/identity.json so a restart keeps its agent id. It holds
// no secret: the credential is the token, not this file.
type Identity struct {
	AgentID string `json:"agent_id"`
}

func defaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Watchtower", "agent")
	case "darwin":
		return "/usr/local/var/wt-agent"
	}
	return "/var/lib/wt-agent"
}

func identityPath(stateDir string) string { return filepath.Join(stateDir, "identity.json") }

// LoadIdentity returns the stored identity, or the zero value when there is none.
func LoadIdentity(stateDir string) (Identity, error) {
	b, err := os.ReadFile(identityPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return Identity{}, nil
	}
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return Identity{}, nil // a torn file counts as no identity: register afresh
	}
	return id, nil
}

// SaveIdentity writes the identity atomically (temp file, fsync, rename).
func SaveIdentity(stateDir string, id Identity) error {
	b, _ := json.Marshal(id)
	return writeFileAtomic(identityPath(stateDir), b, 0o640)
}

// EnsureRegistered registers with the server, presenting the stored id so the server keeps the
// same row, and stores the id it gets back. If the server does not know the stored id (404:
// a new project, a wiped database) it registers afresh under a new id.
func EnsureRegistered(ctx context.Context, f *Fleet, stateDir string, info HostInfo) (Identity, error) {
	id, err := LoadIdentity(stateDir)
	if err != nil {
		return Identity{}, err
	}
	got, err := f.Register(ctx, id.AgentID, info)
	if errors.Is(err, ErrNotFound) && id.AgentID != "" {
		got, err = f.Register(ctx, "", info)
	}
	if err != nil {
		return Identity{}, err
	}
	if got != id.AgentID {
		id.AgentID = got
		if err := SaveIdentity(stateDir, id); err != nil {
			return Identity{}, err
		}
	}
	return id, nil
}
