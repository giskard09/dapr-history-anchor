// Command produce generates a byte-exact Dapr Verifiable Execution history
// signature using Dapr's own durabletask-go/backend/historysigning package,
// then emits the chain head (SignatureDigest) that gets anchored on-chain.
//
// It also generates a SECOND, sibling head (the "fork" head): a validly
// signed HistorySignature claiming the exact same predecessor and
// sequence_range as the first, but a different terminal event — the
// rewind/continue-as-new/compaction scenario an operator-side history chain
// cannot itself distinguish from the true head. See PROVENANCE.md.
//
// PROVENANCE / HONESTY: The HistorySignature below is produced by Dapr's real
// signing code (durabletask-go v0.12.1, Apache-2.0). The SPIFFE SVID is minted
// locally in this program (trust domain spiffe://mycelium.demo) — it is NOT
// issued by a Dapr SPIRE control plane, and the workflow events are synthetic.
// So: the wire format and digest are exactly what Dapr produces; the identity
// behind the signature is ours, declared. This is a worked example, not output
// captured from a running Dapr cluster.
//
// NOTE ON THE COMMITTED HEAD (manifest.json / history_signature.bin): that
// instance is already anchored on Base mainnet (see anchor.json, tx
// 0x8702287dca...). Re-minting it here would produce a different key/
// timestamp and break the byte-match to that on-chain anchor. So this
// program only REGENERATES the head when no existing artifacts are found
// (first-run / fresh outDir); otherwise it loads the committed head A from
// disk untouched and only mints the new fork head (head B) alongside it.
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
	"google.golang.org/protobuf/proto"
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

// mintSigner creates a fresh local SPIFFE SVID (declared: not SPIRE-issued)
// and returns a signer wrapping it plus the leaf certificate DER.
func mintSigner() (*signer.Signer, []byte) {
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
	return signer.New(&staticSVIDSource{svid: svid}, nil), certDER
}

func predecessorHex(prev []byte) string {
	if prev == nil {
		return ""
	}
	return hex.EncodeToString(prev)
}

func main() {
	outDir := "artifacts"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	must(os.MkdirAll(outDir, 0o755))

	write := func(name string, b []byte) {
		must(os.WriteFile(filepath.Join(outDir, name), b, 0o644))
	}

	rawSigPath := filepath.Join(outDir, "history_signature.bin")
	manifestPath := filepath.Join(outDir, "manifest.json")

	var (
		sigA     *protos.HistorySignature
		rawSigA  []byte
		headAHex string
	)

	if existing, err := os.ReadFile(rawSigPath); err == nil {
		// --- Head A already committed and anchored on-chain: load it as-is,
		// never re-mint (a fresh key/timestamp would produce different bytes
		// and break the match to anchor.json's tx). -----------------------
		rawSigA = existing
		sigA = &protos.HistorySignature{}
		must(proto.Unmarshal(rawSigA, sigA))
		headAHex = hex.EncodeToString(historysigning.SignatureDigest(rawSigA))
		fmt.Println("=== dapr-history-anchor : producer ===")
		fmt.Printf("head A: loaded existing committed instance from %s (not re-minted)\n", rawSigPath)
	} else {
		// --- Fresh outDir: mint head A from scratch (first run only) -------
		sA, certA := mintSigner()

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
		raw0, err := historysigning.MarshalEvent(ev0)
		must(err)
		raw1, err := historysigning.MarshalEvent(ev1)
		must(err)
		rawEvents := [][]byte{raw0, raw1}

		res, err := historysigning.Sign(sA, historysigning.SignOptions{
			RawEvents:       rawEvents,
			StartEventIndex: 0,
			// PreviousSignatureRaw nil => root of the chain.
		})
		must(err)

		if err := historysigning.VerifySignature(sA, res.Signature, []*protos.SigningCertificate{
			{Certificate: certA},
		}, rawEvents, nil); err != nil {
			panic(fmt.Sprintf("head A self-verify failed: %v", err))
		}

		sigA = res.Signature
		rawSigA = res.RawSignature
		headAHex = hex.EncodeToString(historysigning.SignatureDigest(rawSigA))

		write("history_signature.bin", rawSigA)
		write("event_0.bin", raw0)
		write("event_1.bin", raw1)
		write("signing_cert.der", certA)

		manifest := map[string]any{
			"description":          "Dapr Verifiable Execution history signature — worked example for permissionless external anchoring.",
			"provenance":           "Produced by Dapr durabletask-go v0.12.1 historysigning.Sign(). SPIFFE SVID minted locally (spiffe://mycelium.demo), NOT SPIRE-issued. Synthetic workflow events. Worked example, not captured from a running Dapr cluster.",
			"dapr_module":          "github.com/dapr/durabletask-go@v0.12.1",
			"signature_algorithm":  "Ed25519 over SHA-256(previousSignatureDigest || eventsDigest)",
			"start_event_index":    sigA.GetStartEventIndex(),
			"event_count":          sigA.GetEventCount(),
			"sequence_range": map[string]any{
				"start_event_index": sigA.GetStartEventIndex(),
				"event_count":       sigA.GetEventCount(),
			},
			"predecessor_signature_digest_hex": predecessorHex(sigA.GetPreviousSignatureDigest()),
			"events_digest_hex":                hex.EncodeToString(sigA.GetEventsDigest()),
			"certificate_index":                sigA.GetCertificateIndex(),
			"raw_signature_len":                len(rawSigA),
			"raw_signature_hex":                hex.EncodeToString(rawSigA),
			"chain_head_digest_hex":            headAHex,
			"anchor_ref_bytes32":               "0x" + headAHex,
			"anchor_registry":                  "0x49fEcA52bC634a9Ab773226D16619deC547794aa",
			"anchor_chain":                     "Base mainnet (chainId 8453)",
			"self_verify":                      "PASS (historysigning.VerifySignature)",
			"generated_at_utc":                 time.Now().UTC().Format(time.RFC3339),
		}
		mb, err := json.MarshalIndent(manifest, "", "  ")
		must(err)
		write("manifest.json", mb)
	}

	// If manifest.json exists but predates the predecessor/sequence_range
	// fields (the already-committed instance), patch them in without
	// touching any existing value — the head must stay byte-identical to
	// what's anchored on-chain.
	if mb, err := os.ReadFile(manifestPath); err == nil {
		var m map[string]any
		must(json.Unmarshal(mb, &m))
		if _, ok := m["predecessor_signature_digest_hex"]; !ok {
			m["predecessor_signature_digest_hex"] = predecessorHex(sigA.GetPreviousSignatureDigest())
		}
		if _, ok := m["sequence_range"]; !ok {
			m["sequence_range"] = map[string]any{
				"start_event_index": sigA.GetStartEventIndex(),
				"event_count":       sigA.GetEventCount(),
			}
		}
		patched, err := json.MarshalIndent(m, "", "  ")
		must(err)
		write("manifest.json", patched)
	}

	// --- Head B: the fork ----------------------------------------------------
	// Simulate a rewind: an operator, holding a (possibly rotated) signing
	// identity, re-signs an alternate history from the SAME starting point as
	// head A — StartEventIndex 0, PreviousSignatureRaw nil, i.e. the identical
	// predecessor claim (genesis: no predecessor). The genesis event content
	// (ExecutionStarted, same workflow/input) is reproduced; only the
	// terminal event is rewritten, from COMPLETED/"shipped" to FAILED/
	// "payment declined". This is the exact class of divergence a
	// history-signature chain alone cannot detect: two individually valid
	// signatures, both claiming the same sequence_range and the same
	// predecessor, disagreeing on outcome. Anchoring both heads externally
	// makes the divergence observable to a verifier who was not present when
	// either was produced.
	sB, certB := mintSigner()

	baseB := time.Now().UTC()
	ev0Fork := &protos.HistoryEvent{
		EventId:   0,
		Timestamp: timestamppb.New(baseB),
		EventType: &protos.HistoryEvent_ExecutionStarted{
			ExecutionStarted: &protos.ExecutionStartedEvent{
				Name:  "OrderWorkflow",
				Input: wrapperspb.String(`{"orderId":"MYC-1001","amount":42}`),
			},
		},
	}
	ev1Fork := &protos.HistoryEvent{
		EventId:   1,
		Timestamp: timestamppb.New(baseB.Add(2 * time.Second)),
		EventType: &protos.HistoryEvent_ExecutionCompleted{
			ExecutionCompleted: &protos.ExecutionCompletedEvent{
				WorkflowStatus: protos.OrchestrationStatus_ORCHESTRATION_STATUS_FAILED,
				Result:         wrapperspb.String(`{"status":"payment declined"}`),
			},
		},
	}
	raw0Fork, err := historysigning.MarshalEvent(ev0Fork)
	must(err)
	raw1Fork, err := historysigning.MarshalEvent(ev1Fork)
	must(err)
	rawEventsFork := [][]byte{raw0Fork, raw1Fork}

	resFork, err := historysigning.Sign(sB, historysigning.SignOptions{
		RawEvents:       rawEventsFork,
		StartEventIndex: 0,
		// PreviousSignatureRaw nil => same genesis predecessor as head A.
	})
	must(err)

	if err := historysigning.VerifySignature(sB, resFork.Signature, []*protos.SigningCertificate{
		{Certificate: certB},
	}, rawEventsFork, nil); err != nil {
		panic(fmt.Sprintf("head B (fork) self-verify failed: %v", err))
	}

	headBHex := hex.EncodeToString(historysigning.SignatureDigest(resFork.RawSignature))

	write("history_signature_fork.bin", resFork.RawSignature)
	write("event_0_fork.bin", raw0Fork)
	write("event_1_fork.bin", raw1Fork)
	write("signing_cert_fork.der", certB)

	manifestFork := map[string]any{
		"description":          "Dapr Verifiable Execution history signature — SIBLING head to manifest.json: same predecessor claim (genesis, no predecessor) and same sequence_range, rewritten terminal event. Demonstrates the rewind/fork scenario raised in dapr/dapr#10191 by 0xbrainkid: a history-signature chain alone cannot distinguish which of two validly-signed heads sharing the same predecessor and sequence_range is the 'true' one.",
		"provenance":           "Produced by Dapr durabletask-go v0.12.1 historysigning.Sign(). SPIFFE SVID minted locally (spiffe://mycelium.demo), NOT SPIRE-issued, independent key from head A (a rotated/second operator identity is the more adversarial case; the predecessor+range collision does not depend on key reuse). Genesis event (ExecutionStarted, same workflow/input) reproduced; only the terminal event differs: COMPLETED/shipped (head A, manifest.json) vs FAILED/payment-declined (head B, this file). Worked example, not captured from a running Dapr cluster.",
		"dapr_module":          "github.com/dapr/durabletask-go@v0.12.1",
		"signature_algorithm":  "Ed25519 over SHA-256(previousSignatureDigest || eventsDigest)",
		"start_event_index":    resFork.Signature.GetStartEventIndex(),
		"event_count":          resFork.Signature.GetEventCount(),
		"sequence_range": map[string]any{
			"start_event_index": resFork.Signature.GetStartEventIndex(),
			"event_count":       resFork.Signature.GetEventCount(),
		},
		"predecessor_signature_digest_hex": predecessorHex(resFork.Signature.GetPreviousSignatureDigest()),
		"events_digest_hex":                hex.EncodeToString(resFork.Signature.GetEventsDigest()),
		"certificate_index":                resFork.Signature.GetCertificateIndex(),
		"raw_signature_len":                len(resFork.RawSignature),
		"raw_signature_hex":                hex.EncodeToString(resFork.RawSignature),
		"chain_head_digest_hex":            headBHex,
		"anchor_ref_bytes32":               "0x" + headBHex,
		"anchor_registry":                  "0x49fEcA52bC634a9Ab773226D16619deC547794aa",
		"anchor_chain":                     "Base mainnet (chainId 8453)",
		"self_verify":                      "PASS (historysigning.VerifySignature)",
		"sibling_of_chain_head_digest_hex": headAHex,
		"relation_to_head_a":               "fork (identical predecessor_signature_digest_hex and sequence_range as manifest.json's head, different chain_head_digest_hex)",
		"generated_at_utc":                 time.Now().UTC().Format(time.RFC3339),
	}
	mbFork, err := json.MarshalIndent(manifestFork, "", "  ")
	must(err)
	write("manifest_fork.json", mbFork)

	fmt.Printf("CHAIN HEAD A (existing, anchored):        0x%s\n", headAHex)
	fmt.Printf("CHAIN HEAD B (fork, same predecessor+range, to anchor): 0x%s\n", headBHex)
	fmt.Printf("artifacts written to: %s/\n", outDir)
}
