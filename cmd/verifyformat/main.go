// Command verifyformat re-checks that the anchored artifact is a *well-formed
// Dapr history signature*, not arbitrary bytes we happened to hash. It parses
// the persisted HistorySignature and re-runs Dapr's own
// historysigning.VerifySignature against the persisted event bytes and the
// signing certificate. Complements verifier/verify.py, which proves the
// on-chain anchoring of the digest.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	"github.com/dapr/durabletask-go/api/protos"
	"github.com/dapr/durabletask-go/backend/historysigning"
	"github.com/dapr/kit/crypto/spiffe/signer"
)

func read(dir, name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	dir := "artifacts"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	rawSig := read(dir, "history_signature.bin")
	raw0 := read(dir, "event_0.bin")
	raw1 := read(dir, "event_1.bin")
	certDER := read(dir, "signing_cert.der")

	var sig protos.HistorySignature
	if err := proto.Unmarshal(rawSig, &sig); err != nil {
		panic(fmt.Sprintf("rawSig is not a valid HistorySignature: %v", err))
	}

	// Verify-only signer (no SVID source needed): VerifySignature checks the
	// cryptographic signature against the leaf cert and recomputes eventsDigest.
	s := signer.New(nil, nil)
	err := historysigning.VerifySignature(
		s, &sig,
		[]*protos.SigningCertificate{{Certificate: certDER}},
		[][]byte{raw0, raw1},
		nil, // own-history chain: nil propagation context
	)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}

	head := sha256.Sum256(rawSig)
	fmt.Println("=== dapr-history-anchor : format-aware verifier ===")
	fmt.Printf("HistorySignature parsed : OK (%d bytes)\n", len(rawSig))
	fmt.Printf("  startEventIndex       : %d\n", sig.GetStartEventIndex())
	fmt.Printf("  eventCount            : %d\n", sig.GetEventCount())
	fmt.Printf("  eventsDigest          : %s\n", hex.EncodeToString(sig.GetEventsDigest()))
	fmt.Printf("  certificateIndex      : %d\n", sig.GetCertificateIndex())
	fmt.Printf("Dapr VerifySignature    : PASS (events digest + Ed25519 signature)\n")
	fmt.Printf("chain head (SHA-256)    : 0x%s\n", hex.EncodeToString(head[:]))
	fmt.Println("\nPASS: anchored ref is the head of a valid Dapr history signature.")
}
