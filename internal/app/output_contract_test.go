package app

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func schemaFormat() map[string]interface{} {
	var value map[string]interface{}
	_ = json.Unmarshal([]byte(`{"type":"json_schema","json_schema":{"name":"Result","strict":true,"schema":{"type":"object","properties":{"total":{"type":"integer"}},"required":["total"],"additionalProperties":false}}}`), &value)
	return value
}

func TestOutputContract(t *testing.T) {
	c, err := parseOutputContract(schemaFormat())
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{`{"total":42}`, "```json\n{\"total\":42}\n```"} {
		got, err := c.validate(text, nil)
		if err != nil || got != `{"total":42}` {
			t.Fatalf("valid output rejected: %q %v", got, err)
		}
	}
	for _, text := range []string{`The total is 42.`, `{"total":"42"}`, `{}`, `{"total":42,"extra":true}`, `{"total":42} {}`} {
		if _, err := c.validate(text, nil); err == nil {
			t.Fatalf("invalid output accepted: %s", text)
		}
	}
	calls := []ToolCall{{ID: "a", Type: "function", Function: ToolCallFunction{Name: "add", Arguments: `{"a":17,"b":25}`}}}
	if text, err := c.validate("I am using a tool", calls); err != nil || text != "" {
		t.Fatalf("tool turn incorrectly validated as final: %q %v", text, err)
	}
	object, _ := parseOutputContract(map[string]interface{}{"type": "json_object"})
	if _, err := object.validate(`[]`, nil); err == nil {
		t.Fatal("array accepted for json_object")
	}
	messages := []map[string]interface{}{{"role": "user", "content": "Find the total"}}
	enriched := c.messages(messages)
	if len(messages) != 1 || len(enriched) != 2 || !strings.Contains(getStr(enriched[0], "content"), `"total"`) {
		t.Fatal("schema instructions missing or caller history mutated")
	}
}

func TestOutputContractRejectsExternalReferences(t *testing.T) {
	for _, schema := range []any{map[string]interface{}{"$ref": "http://127.0.0.1/secrets"}, map[string]interface{}{"$ref": "file:///etc/passwd"}, map[string]interface{}{"type": "bogus"}} {
		format := schemaFormat()
		format["json_schema"].(map[string]interface{})["schema"] = schema
		if _, err := parseOutputContract(format); err == nil {
			t.Fatal("invalid/external schema accepted")
		}
	}
	for _, raw := range []any{"json", map[string]interface{}{"type": "unknown"}, map[string]interface{}{"type": "json_schema"}} {
		if _, err := parseOutputContract(raw); err == nil {
			t.Fatal("invalid format accepted")
		}
	}
	format := schemaFormat()
	format["json_schema"].(map[string]interface{})["schema"] = map[string]interface{}{"$defs": map[string]interface{}{"number": map[string]interface{}{"type": "integer"}}, "$ref": "#/$defs/number"}
	if _, err := parseOutputContract(format); err != nil {
		t.Fatalf("local definition rejected: %v", err)
	}
}

func toolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{{"type": "function", "function": map[string]interface{}{"name": "add", "parameters": map[string]interface{}{"type": "object"}}}}
}

func TestParallelPromptAndCallIdentity(t *testing.T) {
	messages := []map[string]interface{}{
		{"role": "user", "content": "Add two pairs independently"},
		{"role": "assistant", "tool_calls": []interface{}{
			map[string]interface{}{"id": "call_a", "function": map[string]interface{}{"name": "add", "arguments": "{}"}},
			map[string]interface{}{"id": "call_b", "function": map[string]interface{}{"name": "add", "arguments": "{}"}},
		}},
		{"role": "tool", "tool_call_id": "call_b", "content": "9"},
		{"role": "tool", "tool_call_id": "call_a", "content": "42"},
	}
	parallel, _ := messagesToPrompt(messages, toolDefinitions(), nil, true)
	if !strings.Contains(parallel, "INDEPENDENT") || strings.Contains(parallel, "Do not output more than one") {
		t.Fatal("parallel contract contradicted")
	}
	for _, marker := range []string{"Tool call ID: call_a", "Tool call ID: call_b", "add (call_id=call_a)", "add (call_id=call_b)"} {
		if !strings.Contains(parallel, marker) {
			t.Fatalf("missing call identity %s", marker)
		}
	}
	single, _ := messagesToPrompt(messages, toolDefinitions(), nil, false)
	if !strings.Contains(single, "Do not output more than one") {
		t.Fatal("serial contract lost")
	}
}

func TestChatStructuredStreamingAndNonStreaming(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, valid := range []bool{false, true} {
			request := map[string]interface{}{"model": "gemini-3.5-flash-lite", "stream": stream, "response_format": schemaFormat(), "messages": []map[string]interface{}{{"role": "user", "content": "Return total 42"}}}
			body, _ := json.Marshal(request)
			recorder := httptest.NewRecorder()
			generated := false
			handleChatWith(recorder, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(body))), func(prompt, latest string, mc ModelConfig, tools []map[string]interface{}, images []pendingUpload, onDelta, onReasoning func(string)) (string, []ToolCall, *StreamResult, error) {
				generated = true
				if !strings.Contains(prompt, `"total"`) || latest != "Return total 42" {
					t.Fatal("schema or brief lost")
				}
				if onDelta != nil {
					t.Fatal("unvalidated JSON would leak through streaming")
				}
				if valid {
					return `{"total":42}`, nil, &StreamResult{}, nil
				}
				return `not-json`, nil, &StreamResult{}, nil
			})
			if !generated {
				t.Fatalf("fake upstream not called: %d %s", recorder.Code, recorder.Body.String())
			}
			if valid && (recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `\"total\":42`)) {
				t.Fatalf("valid output missing: %d %s", recorder.Code, recorder.Body.String())
			}
			if !valid && (recorder.Code != 502 || strings.Contains(recorder.Body.String(), "not-json")) {
				t.Fatalf("invalid result leaked as success: %d %s", recorder.Code, recorder.Body.String())
			}
			if valid && stream && !strings.Contains(recorder.Body.String(), "[DONE]") {
				t.Fatal("missing stream terminator")
			}
		}
	}
}

func TestChatParallelToolTurnsAndStreamErrors(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		request := map[string]interface{}{"model": "gemini-3.5-flash-lite", "stream": true, "parallel_tool_calls": parallel, "response_format": schemaFormat(), "tools": toolDefinitions(), "messages": []map[string]interface{}{{"role": "user", "content": "Use two independent additions"}}}
		body, _ := json.Marshal(request)
		recorder := httptest.NewRecorder()
		handleChatWith(recorder, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(body))), func(prompt, latest string, mc ModelConfig, tools []map[string]interface{}, images []pendingUpload, onDelta, onReasoning func(string)) (string, []ToolCall, *StreamResult, error) {
			if onReasoning != nil {
				onReasoning("Checking the request")
			}
			return "", []ToolCall{
				{ID: "call_a", Type: "function", Function: ToolCallFunction{Name: "add", Arguments: `{"a":17,"b":25}`}},
				{ID: "call_b", Type: "function", Function: ToolCallFunction{Name: "add", Arguments: `{"a":4,"b":5}`}},
			}, &StreamResult{}, nil
		})
		output := recorder.Body.String()
		if parallel {
			for _, expected := range []string{`"id":"call_a"`, `"id":"call_b"`, `"index":1`, `"finish_reason":"tool_calls"`, `[DONE]`} {
				if !strings.Contains(output, expected) {
					t.Fatalf("missing %s from %s", expected, output)
				}
			}
		} else if !strings.Contains(output, `"error"`) || strings.Contains(output, `"finish_reason":"tool_calls"`) || strings.Contains(output, `"id":"call_a"`) {
			t.Fatalf("serial violation did not fail closed after streaming started: %s", output)
		}
	}
}
