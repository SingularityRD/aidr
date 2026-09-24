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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mcpFixture struct {
	root      string
	server    string
	appConfig string
}

func newMCPFixture(t *testing.T) mcpFixture {
	t.Helper()
	root := t.TempDir()
	packageDir := filepath.Join(root, "src", "mcp_server")
	require.NoError(t, os.MkdirAll(packageDir, 0o700))

	server := filepath.Join(packageDir, "server.py")
	serverContents := "" +
		"from config import AppConfig\n" +
		"@mcp.tool()\n" +
		"def scan():\n" +
		"    transport = 'SSE'\n" +
		"    client = 'EventSource'\n" +
		"    return transport, client\n"
	require.NoError(t, os.WriteFile(server, []byte(serverContents), 0o600))

	appConfig := filepath.Join(packageDir, "app_config.py")
	require.NoError(t, os.WriteFile(appConfig, []byte("class AppConfig:\n    enabled = True\n"), 0o600))

	return mcpFixture{root: root, server: server, appConfig: appConfig}
}

func TestListDir(t *testing.T) {
	fixture := newMCPFixture(t)
	listing, err := ListDir(fixture.root, -1, "")
	require.NoError(t, err)
	assert.Contains(t, listing, "server.py")
	assert.Contains(t, listing, "app_config.py")
}

func TestGrepFile(t *testing.T) {
	fixture := newMCPFixture(t)
	result, err := Grep(fixture.server, `@mcp\.tool\(\)\n.*def`, 3)
	require.NoError(t, err)
	assert.Contains(t, result, "def scan")
}

func TestGrepDirectory(t *testing.T) {
	fixture := newMCPFixture(t)

	result, err := Grep(fixture.root, "AppConfig", 3)
	require.NoError(t, err)
	assert.Contains(t, result, "AppConfig")

	result, err = Grep(fixture.root, "SSE|streamable-http|EventSource", 3)
	require.NoError(t, err)
	assert.Contains(t, result, "EventSource")
}

func TestReadBigFile(t *testing.T) {
	fixture := newMCPFixture(t)

	result, err := ReadFileChunk(fixture.server, 0, 0, 32)
	require.NoError(t, err)
	assert.Contains(t, result, "AppConfig")

	result, err = ReadFileChunk(fixture.server, 2, 3, 10*1024)
	require.NoError(t, err)
	assert.Contains(t, result, "def scan")
}

func TestReadSmallFile(t *testing.T) {
	fixture := newMCPFixture(t)
	result, err := ReadFileChunk(fixture.appConfig, 0, 0, 10*1024)
	require.NoError(t, err)
	assert.Contains(t, result, "class AppConfig")
}
