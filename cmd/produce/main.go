// Command produce generates a byte-exact Dapr Verifiable Execution history
// signature using Dapr's own durabletask-go/backend/historysigning package,
// then emits the chain head (SignatureDigest) that gets anchored on-chain.
//
// PROVENANCE / HONESTY: The HistorySignature below is produced by Dapr's real
// signing code (durabletask-go v0.12.1, Apache-2.0). The SPIFFE SVID is minted
// locally in this program (trust domain spiffe://mycelium.demo) — it is NOT
// issued by a Dapr SPIRE control plane, and the workflow events are synthetic.
// So: the wire format and digest are exactly what Dapr produces; the identity
// behind the signature is ours, declared. This is a worked example, not output
// captured from a running Dapr cluster.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/dapr/durabletask-go/api/protos"
	"github.com/dapr/durabletask-go/backend/historysigning"
	"github.com/dapr/kit/crypto/spiffe/signer"
)

// staticSVIDSource is a minimal x509svid.Source backed by an in-memory SVID.
// This is the only "plumbing" we add — everything cryptographic and every byte
// of the HistorySignature comes from Dapr's own packages.
type staticSVIDSource struct{ svid *x509svid.SVID }

func (s *staticSVIDSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	outDir := "artifacts"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	must(os.MkdirAll(outDir, 0o755))

	// --- 1. Mint a local SPIFFE SVID (declared: not SPIRE-issued) -----------
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)

	spiffeID, err := spiffeid.FromString("spiffe://mycelium.demo/dapr-history-anchor/worked-example")
	must(err)

	notBefore := time.Now().Add(-1 * time.Hour).UTC()
	notAfter := notBefore.Add(48 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mycelium-worked-example"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffeID.URL()},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	must(err)
	leaf, err := x509.ParseCertificate(certDER)
	must(err)

	svid := &x509svid.SVID{
		ID:           spiffeID,
		Certificates: []*x509.Certificate{leaf},
		PrivateKey:   priv,
	}
	s := signer.New(&staticSVIDSource{svid: svid}, nil)

	// --- 2. Build a synthetic 2-event workflow history ----------------------
	base := time.Now().UTC()
	ev0 := &protos.HistoryEvent{
		EventId:   0,
		Timestamp: timestamppb.New(base),
		EventType: &protos.HistoryEvent_ExecutionStarted{
			ExecutionStarted: &protos.ExecutionStartedEvent{
				Name:  "OrderWorkflow",
				Input: wrapperspb.String(`{"orderId":"MYC-1001","amount":42}`),
			},
		},
	}
	ev1 := &protos.HistoryEvent{
		EventId:   1,
		Timestamp: timestamppb.New(base.Add(2 * time.Second)),
		EventType: &protos.HistoryEvent_ExecutionCompleted{
			ExecutionCompleted: &protos.ExecutionCompletedEvent{
				WorkflowStatus: protos.OrchestrationStatus_ORCHESTRATION_STATUS_COMPLETED,
				Result:         wrapperspb.String(`{"status":"shipped"}`),
			},
		},
	}

	// Marshal events with Dapr's deterministic marshaler. These raw bytes are
	// exactly what would be persisted to the state store (one per history key)
	// and are the single source of truth for both signing and verification.
	raw0, err := historysigning.MarshalEvent(ev0)
	must(err)
	raw1, err := historysigning.MarshalEvent(ev1)
	must(err)
	rawEvents := [][]byte{raw0, raw1}

	// --- 3. Sign with Dapr's own historysigning.Sign -----------------------
	res, err := historysigning.Sign(s, historysigning.SignOptions{
		RawEvents:       rawEvents,
		StartEventIndex: 0,
		// PreviousSignatureRaw nil => root of the chain.
		// ExistingCerts nil => this cert is appended at index 0.
	})
	must(err)

	// --- 4. Compute the chain head — the value we anchor on-chain -----------
	// SignatureDigest = SHA-256(exact persisted rawSig). Per Dapr's own code:
	// never re-marshal the struct; hash the persisted bytes.
	head := historysigning.SignatureDigest(res.RawSignature)
	headHex := hex.EncodeToString(head)

	// --- 5. Self-check: re-verify the signature with Dapr's verifier --------
	// (Cryptographic + events-digest check; no trust-anchor plumbing needed.)
	if err := historysigning.VerifySignature(s, res.Signature, []*protos.SigningCertificate{
		{Certificate: res.NewCert.GetCertificate()},
	}, rawEvents, nil); err != nil {
		panic(fmt.Sprintf("self-verify failed: %v", err))
	}

	// --- 6. Emit artifacts --------------------------------------------------
	write := func(name string, b []byte) {
		must(os.WriteFile(filepath.Join(outDir, name), b, 0o644))
	}
	write("history_signature.bin", res.RawSignature) // the exact persisted HistorySignature
	write("event_0.bin", raw0)
	write("event_1.bin", raw1)
	write("signing_cert.der", res.NewCert.GetCertificate())

	manifest := map[string]any{
		"description":            "Dapr Verifiable Execution history signature — worked example for permissionless external anchoring.",
		"provenance":             "Produced by Dapr durabletask-go v0.12.1 historysigning.Sign(). SPIFFE SVID minted locally (spiffe://mycelium.demo), NOT SPIRE-issued. Synthetic workflow events. Worked example, not captured from a running Dapr cluster.",
		"dapr_module":            "github.com/dapr/durabletask-go@v0.12.1",
		"signature_algorithm":    "Ed25519 over SHA-256(previousSignatureDigest || eventsDigest)",
		"start_event_index":      res.Signature.GetStartEventIndex(),
		"event_count":            res.Signature.GetEventCount(),
		"events_digest_hex":      hex.EncodeToString(res.Signature.GetEventsDigest()),
		"certificate_index":      res.Signature.GetCertificateIndex(),
		"raw_signature_len":      len(res.RawSignature),
		"raw_signature_hex":      hex.EncodeToString(res.RawSignature),
		"chain_head_digest_hex":  headHex,               // SHA-256(rawSig)
		"anchor_ref_bytes32":     "0x" + headHex,         // exactly what anchor(bytes32) receives
		"anchor_registry":        "0x49fEcA52bC634a9Ab773226D16619deC547794aa",
		"anchor_chain":           "Base mainnet (chainId 8453)",
		"self_verify":            "PASS (historysigning.VerifySignature)",
		"generated_at_utc":       time.Now().UTC().Format(time.RFC3339),
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	write("manifest.json", mb)

	fmt.Println("=== dapr-history-anchor : producer ===")
	fmt.Printf("rawSig bytes:        %d\n", len(res.RawSignature))
	fmt.Printf("events digest:       %s\n", hex.EncodeToString(res.Signature.GetEventsDigest()))
	fmt.Printf("self-verify:         PASS\n")
	fmt.Printf("CHAIN HEAD (anchor): 0x%s\n", headHex)
	fmt.Printf("artifacts written to: %s/\n", outDir)
}
