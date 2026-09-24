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
	"encoding/json"
	"fmt"
	"strings"

	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLargeDataSend 测试发送大字节数据
func TestLargeDataSend(t *testing.T) {
	// Create an agent without connecting; this unit test verifies queueing and
	// serialization, while WebSocket transport is covered by server tests.
	agent := NewAgent(AgentConfig{
		ServerURL: "ws://example.invalid/api/v1/agents/ws",
		Info: AgentInfo{
			ID:       "test-large-data",
			HostName: "test-host",
			IP:       "127.0.0.1",
			Version:  "0.1",
			Metadata: "",
		},
	})
	// 创建大数据内容 - 生成约1MB的数据
	largeContent := generateLargeContent(1024 * 1024) // 1MB

	// 创建包含大数据的任务结果
	largeResult := map[string]interface{}{
		"type":        "large_data_test",
		"data_size":   len(largeContent),
		"content":     largeContent,
		"description": "测试发送大字节数据的能力",
		"metadata": map[string]interface{}{
			"compression": false,
			"encoding":    "utf-8",
			"chunks":      1,
		},
	}

	// 测试序列化大数据
	jsonData, err := json.Marshal(largeResult)
	assert.NoError(t, err, "大数据JSON序列化应该成功")

	dataSize := len(jsonData)
	t.Logf("生成的JSON数据大小: %d bytes (%.2f MB)", dataSize, float64(dataSize)/(1024*1024))

	err = agent.SendTaskResult("test-session-large-data", largeResult)
	assert.NoError(t, err, "发送大数据任务结果应该成功")

	message := (<-agent.sendChan).(RequestData)
	assert.Equal(t, AgentMsgTypeResultUpdate, message.Type)
	result := message.Content.(ResultUpdate)
	assert.Equal(t, "test-session-large-data", result.SessionId)
	assert.Equal(t, largeContent, result.Event.Result["content"])
}

// generateLargeContent 生成指定大小的大内容
func generateLargeContent(size int) string {
	// 创建基础模板
	template := "这是一段测试数据，用于验证大字节数据的传输能力。包含中文字符以测试编码处理。Data chunk %d. "

	var builder strings.Builder
	builder.Grow(size) // 预分配容量

	chunkCount := 0
	for builder.Len() < size {
		chunk := fmt.Sprintf(template, chunkCount)
		if builder.Len()+len(chunk) > size {
			// 添加剩余字符直到达到目标大小
			remaining := size - builder.Len()
			builder.WriteString(chunk[:remaining])
			break
		}
		builder.WriteString(chunk)
		chunkCount++
	}

	return builder.String()
}
