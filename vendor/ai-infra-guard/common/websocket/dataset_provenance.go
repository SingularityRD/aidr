// Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package websocket

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type dataManifestSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	TreeSHA256 string `json:"tree_sha256"`
}

type dataManifestArtifact struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type dataManifestCounts struct {
	CVEs          int `json:"cves"`
	Fingerprints  int `json:"fingerprints"`
	MCPCategories int `json:"mcp_categories"`
}

type runtimeDataManifest struct {
	Schema     string `json:"schema"`
	Root       string `json:"root"`
	TreeSHA256 string `json:"tree_sha256"`
	Files      int    `json:"files"`
	Bytes      int64  `json:"bytes"`
}

type dataManifestSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

type dataManifestPayload struct {
	Schema          string                          `json:"schema"`
	Generated       string                          `json:"generated"`
	ReleaseSequence int                             `json:"release_sequence"`
	Source          dataManifestSource              `json:"source"`
	BundleID        string                          `json:"bundle_id"`
	Artifacts       map[string]dataManifestArtifact `json:"artifacts"`
	Counts          dataManifestCounts              `json:"counts"`
	Runtime         runtimeDataManifest             `json:"runtime"`
}

type signedDataManifest struct {
	dataManifestPayload
	Signature *dataManifestSignature `json:"signature"`
}

type datasetProvenanceEvidence struct {
	Verified        bool   `json:"verified"`
	BundleID        string `json:"bundle_id,omitempty"`
	SourceCommit    string `json:"source_commit,omitempty"`
	ReleaseSequence int    `json:"release_sequence,omitempty"`
}

type runtimeDataFile struct {
	path   string
	digest [sha256.Size]byte
	bytes  int64
}

func datasetReadinessStatus(evidence datasetProvenanceEvidence) int {
	if !evidence.Verified {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func verifyDatasetProvenanceFromEnvironment() (datasetProvenanceEvidence, error) {
	manifestPath := strings.TrimSpace(os.Getenv("AIG_DATA_MANIFEST_PATH"))
	dataRoot := strings.TrimSpace(os.Getenv("AIG_DATA_ROOT"))
	publicKeyPath := strings.TrimSpace(os.Getenv("AIG_SIGNING_PUBLIC_KEY_PATH"))
	trustedKeyID := strings.TrimSpace(os.Getenv("AIG_TRUSTED_SIGNING_KEY_ID"))
	trustedFingerprint := strings.ToLower(strings.TrimSpace(os.Getenv("AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256")))
	expectedBundle := strings.ToLower(strings.TrimSpace(os.Getenv("AIG_EXPECTED_DATA_BUNDLE_ID")))
	expectedCommit := strings.ToLower(strings.TrimSpace(os.Getenv("AIG_EXPECTED_SOURCE_COMMIT")))
	if manifestPath == "" || dataRoot == "" || publicKeyPath == "" || trustedKeyID == "" ||
		!validHex(trustedFingerprint, sha256.Size) || !validHex(expectedBundle, sha256.Size) || !validHex(expectedCommit, 20) {
		return datasetProvenanceEvidence{}, errors.New("AIG dataset trust policy is incomplete or invalid")
	}
	if !filepath.IsAbs(manifestPath) || !filepath.IsAbs(dataRoot) || !filepath.IsAbs(publicKeyPath) {
		return datasetProvenanceEvidence{}, errors.New("AIG dataset trust paths must be absolute")
	}

	manifestBytes, err := readBoundedRegularFile(manifestPath, 1024*1024)
	if err != nil {
		return datasetProvenanceEvidence{}, fmt.Errorf("read AIG data manifest: %w", err)
	}
	var manifest signedDataManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return datasetProvenanceEvidence{}, errors.New("AIG data manifest is invalid")
	}
	if manifest.Schema != "aig-data-manifest/v1" || manifest.ReleaseSequence < 1 ||
		!validHex(manifest.BundleID, sha256.Size) || !validHex(manifest.Source.Commit, 20) ||
		!validHex(manifest.Source.TreeSHA256, sha256.Size) || manifest.Runtime.Schema != "aig-runtime-data/v1" ||
		manifest.Runtime.Root != "data" || !validHex(manifest.Runtime.TreeSHA256, sha256.Size) ||
		manifest.Runtime.Files < 1 || manifest.Runtime.Bytes < 1 {
		return datasetProvenanceEvidence{}, errors.New("AIG data manifest schema is invalid")
	}
	if manifest.BundleID != expectedBundle || manifest.Source.Commit != expectedCommit {
		return datasetProvenanceEvidence{}, errors.New("AIG data manifest does not match deployment pins")
	}
	if manifest.Signature == nil || manifest.Signature.Algorithm != "RSA-SHA256" ||
		manifest.Signature.KeyID != trustedKeyID || manifest.Signature.Value == "" {
		return datasetProvenanceEvidence{}, errors.New("AIG data manifest signature policy failed")
	}

	publicKeyBytes, err := readBoundedRegularFile(publicKeyPath, 64*1024)
	if err != nil {
		return datasetProvenanceEvidence{}, fmt.Errorf("read AIG signing public key: %w", err)
	}
	block, rest := pem.Decode(publicKeyBytes)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return datasetProvenanceEvidence{}, errors.New("AIG signing public key is invalid")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return datasetProvenanceEvidence{}, errors.New("AIG signing public key is invalid")
	}
	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() < 2048 {
		return datasetProvenanceEvidence{}, errors.New("AIG signing public key must be RSA with at least 2048 bits")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || hex.EncodeToString(sha256Bytes(publicDER)) != trustedFingerprint {
		return datasetProvenanceEvidence{}, errors.New("AIG signing public key is not trusted")
	}
	payload, err := json.Marshal(manifest.dataManifestPayload)
	if err != nil {
		return datasetProvenanceEvidence{}, errors.New("AIG data manifest payload is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(manifest.Signature.Value)
	payloadDigest := sha256.Sum256(payload)
	if err != nil || rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, payloadDigest[:], signature) != nil {
		return datasetProvenanceEvidence{}, errors.New("AIG data manifest signature verification failed")
	}

	runtimeDigest, runtimeFiles, runtimeBytes, err := digestRuntimeDataTree(dataRoot, manifest.Runtime.Root)
	if err != nil {
		return datasetProvenanceEvidence{}, fmt.Errorf("verify AIG runtime data tree: %w", err)
	}
	if runtimeDigest != manifest.Runtime.TreeSHA256 || runtimeFiles != manifest.Runtime.Files || runtimeBytes != manifest.Runtime.Bytes {
		return datasetProvenanceEvidence{}, errors.New("AIG runtime data tree does not match the signed manifest")
	}
	return datasetProvenanceEvidence{
		Verified:        true,
		BundleID:        manifest.BundleID,
		SourceCommit:    manifest.Source.Commit,
		ReleaseSequence: manifest.ReleaseSequence,
	}, nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func digestRuntimeDataTree(root, manifestRoot string) (string, int, int64, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", 0, 0, errors.New("runtime data root is unavailable or unsafe")
	}
	files := make([]runtimeDataFile, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("runtime data tree contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("runtime data tree contains a non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("runtime data path escapes its root")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		var sum [sha256.Size]byte
		copy(sum[:], digest.Sum(nil))
		files = append(files, runtimeDataFile{
			path:   manifestRoot + "/" + filepath.ToSlash(relative),
			digest: sum,
			bytes:  info.Size(),
		})
		return nil
	})
	if err != nil {
		return "", 0, 0, err
	}
	if len(files) == 0 {
		return "", 0, 0, errors.New("runtime data tree is empty")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	treeDigest := sha256.New()
	var totalBytes int64
	for _, file := range files {
		pathBytes := []byte(file.path)
		if uint64(len(pathBytes)) > uint64(^uint32(0)) {
			return "", 0, 0, errors.New("runtime data path is too long")
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(pathBytes)))
		treeDigest.Write(length[:])
		treeDigest.Write(pathBytes)
		treeDigest.Write(file.digest[:])
		totalBytes += file.bytes
	}
	return hex.EncodeToString(treeDigest.Sum(nil)), len(files), totalBytes, nil
}

func sha256Bytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func validHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes && value == strings.ToLower(value)
}
