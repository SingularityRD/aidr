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

package preload

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/parser"
	"github.com/Tencent/AI-Infra-Guard/pkg/httpx"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerPrint(t *testing.T) {
	if os.Getenv("AIG_RUN_LIVE_FINGERPRINT_TESTS") != "1" {
		t.Skip("set AIG_RUN_LIVE_FINGERPRINT_TESTS=1 with MLflow on 127.0.0.1:5000")
	}
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	assert.NoError(t, err)
	httpOptions := &httpx.HTTPOptions{
		Timeout:          time.Duration(30) * time.Second,
		RetryMax:         3,
		FollowRedirects:  false,
		HTTPProxy:        "",
		Unsafe:           false,
		DefaultUserAgent: httpx.GetRandomUserAgent(),
		Dialer:           dialer,
	}
	hp, err := httpx.NewHttpx(httpOptions)
	assert.NoError(t, err)
	// mlflow
	m := Mlflow{}
	t.Log(m.Match(hp, "http://127.0.0.1:5000/"))
	t.Log(m.GetVersion(hp, "http://127.0.0.1:5000/"))
}

func TestRunner_RunFpReqs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<title>AnythingLLM | Your personal LLM trained on anything</title>"))
	}))
	defer server.Close()

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	require.NoError(t, err)
	httpOptions := &httpx.HTTPOptions{
		Timeout:          time.Duration(3) * time.Second,
		RetryMax:         1,
		FollowRedirects:  false,
		HTTPProxy:        "",
		Unsafe:           false,
		DefaultUserAgent: httpx.GetRandomUserAgent(),
		Dialer:           dialer,
	}
	hp, err := httpx.NewHttpx(httpOptions)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "data", "fingerprints", "anythingllm.yaml"))
	require.NoError(t, err)
	fp, err := parser.InitFingerPrintFromData(data)
	require.NoError(t, err)
	instance := New(hp, []parser.FingerPrint{*fp})
	fps := instance.RunFpReqs(server.URL, 10, 0)
	require.NotEmpty(t, fps)
	assert.Equal(t, "anythingllm", fps[0].Name)
}
