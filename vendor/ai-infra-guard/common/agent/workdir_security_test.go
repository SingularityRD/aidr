package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSharedUploadPathRequiresRelativeContainedRegularFile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AIG_UPLOAD_ROOT", root)
	tenantDir := filepath.Join(root, "tenant-a")
	if err := os.Mkdir(tenantDir, 0700); err != nil {
		t.Fatal(err)
	}
	upload := filepath.Join(tenantDir, "upload-id")
	if err := os.WriteFile(upload, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := sharedUploadPath(filepath.Join("tenant-a", "upload-id"))
	if err != nil {
		t.Fatalf("relative upload rejected: %v", err)
	}
	want, err := filepath.EvalSymlinks(upload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
	if _, err := sharedUploadPath(upload); err == nil {
		t.Fatal("absolute upload path was accepted")
	}
	if _, err := sharedUploadPath(filepath.Join("..", "escape")); err == nil {
		t.Fatal("traversal upload path was accepted")
	}
}
