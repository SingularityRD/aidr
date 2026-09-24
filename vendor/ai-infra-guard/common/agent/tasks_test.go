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

package agent

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireLiveAgentTests(t *testing.T) {
	t.Helper()
	if os.Getenv("AIG_RUN_LIVE_AGENT_TESTS") != "1" {
		t.Skip("set AIG_RUN_LIVE_AGENT_TESTS=1 to run Python-backed agent acceptance tests")
	}
}

func testCallbacks() TaskCallbacks {
	return TaskCallbacks{
		ResultCallback:           func(map[string]interface{}) {},
		ToolUseLogCallback:       func(string, string, string, string) {},
		ToolUsedCallback:         func(string, string, string, []Tool) {},
		NewPlanStepCallback:      func(string, string) {},
		StepStatusUpdateCallback: func(string, string, string, string, string) {},
		PlanUpdateCallback:       func([]SubTask) {},
		ErrorCallback:            func(string) {},
	}
}

func TestTaskImplementationsExposeSupportedNames(t *testing.T) {
	tests := []struct {
		task TaskInterface
		want string
	}{
		{task: &AIInfraScanAgent{}, want: TaskTypeAIInfraScan},
		{task: &McpTask{}, want: TaskTypeMcpScan},
		{task: &ModelRedteamReport{}, want: TaskTypeModelRedteamReport},
		{task: &AgentTask{}, want: TaskTypeAgentScan},
		{task: &SkillTask{}, want: TaskTypeSkillScan},
	}

	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			assert.Equal(t, test.want, test.task.GetName())
		})
	}
}

func TestAIInfraScanAgentExecution(t *testing.T) {
	requireLiveAgentTests(t)

	params, err := json.Marshal(ScanRequest{
		Headers: map[string]string{"User-Agent": "AI-Infra-Guard/1.0"},
		Timeout: 5,
	})
	require.NoError(t, err)

	err = (&AIInfraScanAgent{}).Execute(context.Background(), TaskRequest{
		SessionId: "scan-session-456",
		TaskType:  TaskTypeAIInfraScan,
		Params:    params,
		Timeout:   5,
		Content:   "http://127.0.0.1:5000",
		Language:  "zh",
	}, testCallbacks())
	assert.NoError(t, err)
}

func TestMcpTaskExecutionWithURL(t *testing.T) {
	requireLiveAgentTests(t)

	params, err := json.Marshal(map[string]interface{}{
		"model": map[string]string{
			"model":    "test-model",
			"token":    "test-token",
			"base_url": "http://127.0.0.1:5001/v1",
		},
	})
	require.NoError(t, err)

	err = (&McpTask{}).Execute(context.Background(), TaskRequest{
		SessionId: "mcp-session-789",
		TaskType:  TaskTypeMcpScan,
		Params:    params,
		Timeout:   30,
		Content:   "http://127.0.0.1:5000",
		Language:  "zh",
	}, testCallbacks())
	assert.NoError(t, err)
}

func TestModelRedteamReportExecution(t *testing.T) {
	requireLiveAgentTests(t)

	params, err := json.Marshal(map[string]interface{}{
		"model": []ModelParams{{
			BaseUrl: "http://127.0.0.1:5001/v1",
			Token:   "test-token",
			Model:   "test-model",
		}},
		"eval_model": ModelParams{
			BaseUrl: "http://127.0.0.1:5001/v1",
			Token:   "test-token",
			Model:   "test-model",
		},
	})
	require.NoError(t, err)

	err = (&ModelRedteamReport{}).Execute(context.Background(), TaskRequest{
		SessionId: "redteam-session-202",
		TaskType:  TaskTypeModelRedteamReport,
		Params:    params,
		Timeout:   30,
		Content:   "test prompt",
		Language:  "zh",
	}, testCallbacks())
	assert.NoError(t, err)
}
