// Package relsig is the release signature of an agent package: the fleet server offers it over
// OpAMP and the agent verifies it against its compiled-in release key before applying (P6-FL1).
package relsig

import (
	"crypto/ed25519"
	"fmt"
)

// Message is what the release key signs: a fixed prefix, the package coordinates and its SHA-256.
func Message(version, goos, goarch string, sha256 []byte) []byte {
	return append([]byte(fmt.Sprintf("wt-package/v1\n%s\n%s\n%s\n", version, goos, goarch)), sha256...)
}

// Sign is used by the release pipeline and by tests.
func Sign(priv ed25519.PrivateKey, version, goos, goarch string, sha256 []byte) []byte {
	return ed25519.Sign(priv, Message(version, goos, goarch, sha256))
}

// Verify reports whether sig is the release key's signature of the package. A missing or
// malformed key never verifies.
func Verify(pub ed25519.PublicKey, version, goos, goarch string, sha256, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, Message(version, goos, goarch, sha256), sig)
}
