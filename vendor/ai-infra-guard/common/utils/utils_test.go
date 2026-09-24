// Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Requirement: Any integration or derivative work must explicitly attribute
// Tencent Zhuque Lab (https://github.com/Tencent/AI-Infra-Guard) in its
// documentation or user interface, as detailed in the NOTICE file.

package utils

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tencent/AI-Infra-Guard/pkg/httpx"
	"github.com/hashicorp/go-version"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsFileExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "fixture.txt")
	require.NoError(t, os.WriteFile(file, []byte("fixture"), 0o600))

	assert.True(t, IsFileExists(file))
	assert.True(t, IsFileExists(dir))
	assert.False(t, IsDir(file))
	assert.True(t, IsDir(dir))
	assert.False(t, IsFileExists(filepath.Join(dir, "missing")))
}

func TestCompareVersions(t *testing.T) {
	version1 := "1.0.0"
	version2 := "1.2"
	v := CompareVersions(version1, version2)
	t.Log(v)
}

func TestCompareVersions2(t *testing.T) {
	version1 := "2.13"
	version2 := "2.13.1"
	v1 := version.Must(version.NewVersion(version1))
	v2 := version.Must(version.NewVersion(version2))
	assert.True(t, v1.LessThan(v2))
}

func TestFaviconHash(t *testing.T) {
	wantData := []byte("test favicon")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(wantData)
	}))
	defer server.Close()

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	require.NoError(t, err)
	httpOptions := &httpx.HTTPOptions{
		Timeout:          time.Duration(30) * time.Second,
		RetryMax:         3,
		FollowRedirects:  false,
		Unsafe:           false,
		DefaultUserAgent: httpx.GetRandomUserAgent(),
		Dialer:           dialer,
	}
	hp, err := httpx.NewHttpx(httpOptions)
	require.NoError(t, err)
	resp, err := hp.Get(server.URL, nil)
	require.NoError(t, err)
	assert.Equal(t, FaviconHash(wantData), FaviconHash(resp.Data))
}

func TestGetLocalOpenPorts(t *testing.T) {
	if os.Getenv("AIG_RUN_SYSTEM_TESTS") != "1" {
		t.Skip("set AIG_RUN_SYSTEM_TESTS=1 to inspect host sockets with netstat/lsof")
	}
	op, err := GetLocalOpenPorts()
	assert.NoError(t, err)
	for _, item := range op {
		t.Log(item.Address, item.Port)
	}
}
