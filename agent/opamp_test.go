package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"runtime"
	"testing"

	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/watchtowerobservability/watchtower-agent/internal/relsig"
)

func offer(version string, hash, sig []byte) *protobufs.PackageAvailable {
	return &protobufs.PackageAvailable{Version: version, Hash: hash,
		File: &protobufs.DownloadableFile{DownloadUrl: "https://dl.example.com/a", ContentHash: hash, Signature: sig}}
}

func TestAgentRejectsBadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	sum := sha256.Sum256([]byte("bin"))
	o := &OpAMPClient{PubKey: pub}

	good := relsig.Sign(priv, "2.0.0", runtime.GOOS, runtime.GOARCH, sum[:])
	if err := o.verifyPackage(offer("2.0.0", sum[:], good)); err != nil {
		t.Fatalf("good signature refused: %v", err)
	}
	for name, p := range map[string]*protobufs.PackageAvailable{
		"signed by another key": offer("2.0.0", sum[:], relsig.Sign(otherPriv, "2.0.0", runtime.GOOS, runtime.GOARCH, sum[:])),
		"version swapped":       offer("2.0.1", sum[:], good),
		"hash swapped":          offer("2.0.0", make([]byte, 32), good),
		"no signature":          offer("2.0.0", sum[:], nil),
	} {
		if o.verifyPackage(p) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (&OpAMPClient{}).verifyPackage(offer("2.0.0", sum[:], good)) == nil {
		t.Error("an agent without a release key must refuse every package")
	}
}

func TestRemoteFromYAML(t *testing.T) {
	rc, err := remoteFromYAML([]byte("modules:\n  host:\n    interval: 30s\n"))
	if err != nil || string(rc.Modules["host"]) != `{"interval":"30s"}` {
		t.Fatalf("got %v %v", rc, err)
	}
}
