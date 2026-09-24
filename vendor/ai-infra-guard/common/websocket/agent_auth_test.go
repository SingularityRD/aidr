package websocket

import (
	"net/http/httptest"
	"testing"
)

func TestValidAgentSharedSecret(t *testing.T) {
	secret := "worker-secret-0123456789abcdef0123456789abcdef"
	t.Setenv("AIG_AGENT_SHARED_SECRET", secret)

	request := httptest.NewRequest("GET", "/api/v1/agents/ws", nil)
	if validAgentSharedSecret(request) {
		t.Fatal("missing worker secret was accepted")
	}
	request.Header.Set("X-AIG-Agent-Token", "wrong-worker-secret-0123456789abcdef")
	if validAgentSharedSecret(request) {
		t.Fatal("wrong worker secret was accepted")
	}
	request.Header.Set("X-AIG-Agent-Token", secret)
	if !validAgentSharedSecret(request) {
		t.Fatal("matching worker secret was rejected")
	}
}

func TestValidAgentSharedSecretRejectsWeakConfiguration(t *testing.T) {
	t.Setenv("AIG_AGENT_SHARED_SECRET", "short")
	request := httptest.NewRequest("GET", "/api/v1/agents/ws", nil)
	request.Header.Set("X-AIG-Agent-Token", "short")
	if validAgentSharedSecret(request) {
		t.Fatal("weak configured worker secret was accepted")
	}
}

func TestRedactedParamsForStorageRemovesNestedSecrets(t *testing.T) {
	original := map[string]interface{}{
		"model":      map[string]interface{}{"token": "model-secret", "model": "demo"},
		"headers":    map[string]interface{}{"Authorization": "Bearer target-secret"},
		"agent_data": "api_key: embedded-secret",
	}
	redacted := redactedParamsForStorage(original)
	model := redacted["model"].(map[string]interface{})
	headers := redacted["headers"].(map[string]interface{})
	if model["token"] != "[REDACTED]" || headers["Authorization"] != "[REDACTED]" || redacted["agent_data"] != "[REDACTED]" {
		t.Fatalf("sensitive task parameters were not redacted: %#v", redacted)
	}
	if original["agent_data"] != "api_key: embedded-secret" {
		t.Fatal("redaction mutated the live task payload")
	}
}
