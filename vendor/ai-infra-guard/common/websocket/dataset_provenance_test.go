package websocket

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatasetReadinessStatusFailsClosed(t *testing.T) {
	if got := datasetReadinessStatus(datasetProvenanceEvidence{}); got != http.StatusServiceUnavailable {
		t.Fatalf("unverified dataset returned status %d", got)
	}
	if got := datasetReadinessStatus(datasetProvenanceEvidence{Verified: true}); got != http.StatusOK {
		t.Fatalf("verified dataset returned status %d", got)
	}
}

func signedDatasetFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	if err := os.MkdirAll(filepath.Join(dataRoot, "mcp"), 0o700); err != nil {
		t.Fatal(err)
	}
	dataFile := filepath.Join(dataRoot, "mcp", "rule.yaml")
	if err := os.WriteFile(dataFile, []byte("id: mcp-01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	treeDigest, files, bytes, err := digestRuntimeDataTree(dataRoot, "data")
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "public.pem")
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	payload := dataManifestPayload{
		Schema:          "aig-data-manifest/v1",
		Generated:       "2026-09-22T00:00:00.000Z",
		ReleaseSequence: 3,
		Source: dataManifestSource{
			Repository: "https://github.com/tencent/AI-Infra-Guard",
			Commit:     strings.Repeat("b7", 20),
			TreeSHA256: strings.Repeat("c8", 32),
		},
		BundleID: strings.Repeat("a6", 32),
		Artifacts: map[string]dataManifestArtifact{
			"aig-cve-index.json": {SHA256: strings.Repeat("d9", 32), Bytes: 1},
		},
		Counts: dataManifestCounts{CVEs: 1, Fingerprints: 1, MCPCategories: 1},
		Runtime: runtimeDataManifest{
			Schema: "aig-runtime-data/v1", Root: "data", TreeSHA256: treeDigest, Files: files, Bytes: bytes,
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payloadBytes)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, payloadDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := json.Marshal(signedDataManifest{
		dataManifestPayload: payload,
		Signature: &dataManifestSignature{
			Algorithm: "RSA-SHA256", KeyID: "release-key-3", Value: base64.StdEncoding.EncodeToString(signature),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "aig-data-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AIG_DATA_MANIFEST_PATH", manifestPath)
	t.Setenv("AIG_DATA_ROOT", dataRoot)
	t.Setenv("AIG_SIGNING_PUBLIC_KEY_PATH", publicPath)
	t.Setenv("AIG_TRUSTED_SIGNING_KEY_ID", "release-key-3")
	t.Setenv("AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256", hex.EncodeToString(sha256Bytes(publicDER)))
	t.Setenv("AIG_EXPECTED_DATA_BUNDLE_ID", payload.BundleID)
	t.Setenv("AIG_EXPECTED_SOURCE_COMMIT", payload.Source.Commit)
	return dataFile, payload.BundleID
}

func TestVerifyDatasetProvenanceFromEnvironment(t *testing.T) {
	_, bundleID := signedDatasetFixture(t)

	evidence, err := verifyDatasetProvenanceFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Verified || evidence.BundleID != bundleID || evidence.ReleaseSequence != 3 {
		t.Fatalf("unexpected evidence: %+v", evidence)
	}
}

func TestVerifyDatasetProvenanceRejectsRuntimeMutation(t *testing.T) {
	dataFile, _ := signedDatasetFixture(t)
	if err := os.WriteFile(dataFile, []byte("id: tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := verifyDatasetProvenanceFromEnvironment(); err == nil {
		t.Fatal("expected runtime data mutation to fail verification")
	}
}
