package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func workerWorkDir(name string) (string, error) {
	root := strings.TrimSpace(os.Getenv("AIG_WORK_DIR"))
	if root == "" {
		root = os.TempDir()
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("AIG_WORK_DIR must be absolute")
	}
	dir := filepath.Join(filepath.Clean(root), name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func sharedUploadPath(name string) (string, error) {
	root := strings.TrimSpace(os.Getenv("AIG_UPLOAD_ROOT"))
	if root == "" {
		root = "/app/uploads"
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("attachment must be relative to AIG_UPLOAD_ROOT")
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("attachment is outside AIG_UPLOAD_ROOT")
	}
	candidate := filepath.Join(root, clean)
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("attachment is outside AIG_UPLOAD_ROOT")
	}
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("attachment is not a regular shared upload")
	}
	realRelative, err := filepath.Rel(root, real)
	if err != nil || realRelative == ".." || strings.HasPrefix(realRelative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("attachment is outside AIG_UPLOAD_ROOT")
	}
	info, err := os.Lstat(real)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("attachment is not a regular shared upload")
	}
	return real, nil
}
