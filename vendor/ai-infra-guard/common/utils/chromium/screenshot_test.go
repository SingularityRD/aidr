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

package chromium

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScreenshot(t *testing.T) {
	if os.Getenv("AIG_RUN_BROWSER_TESTS") != "1" {
		t.Skip("set AIG_RUN_BROWSER_TESTS=1 to run the live Chrome screenshot acceptance test")
	}
	instance, err := NewWebScreenShotWithOptions()
	assert.NoError(t, err)
	url := "https://www.baidu.com/"
	data, err := instance.Screen(url)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
	err = os.WriteFile(filepath.Join(t.TempDir(), "screenshot.png"), data, 0o600)
	assert.NoError(t, err)
}
