package app

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func commandTools() []map[string]interface{} {
	return []map[string]interface{}{{"type": "function", "function": map[string]interface{}{
		"name": "exec_command", "parameters": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"cmd": map[string]interface{}{"type": "string"}}, "required": []interface{}{"cmd"}, "additionalProperties": false},
	}}}
}
func commandCall(args string) []ToolCall {
	return []ToolCall{{ID: "call_test", Type: "function", Function: ToolCallFunction{Name: "exec_command", Arguments: args}}}
}
func TestClientArgumentContract(t *testing.T) {
	for _, args := range []string{"null", "[]", "{}", `{"cmd":3}`, `{"cmd":"ls","extra":true}`, "broken"} {
		if validateClientCalls(commandCall(args), commandTools(), "auto", false) == nil {
			t.Fatalf("accepted invalid arguments %s", args)
		}
	}
	if err := validateClientCalls(commandCall(`{"cmd":"printf 'hello\\n' > game.gd"}`), commandTools(), "required", false); err != nil {
		t.Fatal(err)
	}
	if validateClientCalls(nil, commandTools(), "required", false) == nil {
		t.Fatal("required call not enforced")
	}
	if validateClientCalls(commandCall(`{"cmd":"ls"}`), commandTools(), "none", false) == nil {
		t.Fatal("none accepted a call")
	}
	if validateClientCalls(commandCall(`{"cmd":"ls"}`), toolDefinitions(), "auto", false) == nil {
		t.Fatal("unknown tool accepted")
	}
	_, calls := parseToolCalls("```tool_call\n{\"name\":\"exec_command\"}\n```")
	if validateClientCalls(calls, commandTools(), "auto", false) == nil {
		t.Fatal("missing-argument regression")
	}
}
func TestMalformedProposalGetsOnlyOneRepair(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, repaired := range []bool{false, true} {
			request := map[string]interface{}{"model": "gemini-3.5-flash-lite", "stream": stream, "tools": commandTools(), "tool_choice": "required", "messages": []map[string]interface{}{{"role": "user", "content": "Write the game"}}}
			body, _ := json.Marshal(request)
			recorder := httptest.NewRecorder()
			attempts := 0
			handleChatWith(recorder, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(body))), func(prompt, latest string, mc ModelConfig, tools []map[string]interface{}, images []pendingUpload, onDelta, onReasoning func(string)) (string, []ToolCall, *StreamResult, error) {
				attempts++
				if attempts == 2 {
					if !strings.Contains(prompt, "NOT executed") || !strings.Contains(prompt, "never null") {
						t.Fatal("missing corrective feedback")
					}
					if repaired {
						return "", commandCall(`{"cmd":"echo saved"}`), &StreamResult{}, nil
					}
				}
				return "", commandCall("null"), &StreamResult{}, nil
			})
			if attempts != 2 {
				t.Fatalf("repair count %d", attempts)
			}
			if repaired {
				if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "echo saved") || strings.Contains(recorder.Body.String(), `"arguments":"null"`) {
					t.Fatalf("bad successful response: %s", recorder.Body.String())
				}
			} else if recorder.Code != 502 || strings.Contains(recorder.Body.String(), `"tool_calls"`) {
				t.Fatalf("invalid proposal escaped: %s", recorder.Body.String())
			}
		}
	}
}
func TestTransportFailureDoesNotTriggerProposalRepair(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{"model": "gemini-3.5-flash-lite", "tools": commandTools(), "messages": []map[string]interface{}{{"role": "user", "content": "Write the game"}}})
	calls := 0
	recorder := httptest.NewRecorder()
	handleChatWith(recorder, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(body))), func(string, string, ModelConfig, []map[string]interface{}, []pendingUpload, func(string), func(string)) (string, []ToolCall, *StreamResult, error) {
		calls++
		return "", nil, nil, fmt.Errorf("connection interrupted")
	})
	if calls != 1 || recorder.Code != 502 {
		t.Fatalf("transport retry: %d %d", calls, recorder.Code)
	}
}
