package app

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// outputContract adapts Chat Completions response_format to a text-only upstream.
// Schema instructions help generation; validation, not the prompt, enforces success.
type outputContract struct {
	instruction string
	schema      *jsonschema.Schema
	jsonObject  bool
}

type noExternalSchemas struct{}

func (noExternalSchemas) Load(string) (any, error) {
	return nil, fmt.Errorf("external schema references are not supported")
}

func parseOutputContract(raw any) (*outputContract, error) {
	if raw == nil {
		return nil, nil
	}
	format, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("response_format must be an object")
	}
	switch getStr(format, "type") {
	case "text":
		return nil, nil
	case "json_object":
		return &outputContract{jsonObject: true, instruction: "Your final answer MUST be one valid JSON object. Do not add markdown fences or prose. Tool calls, when needed, still use tool_call blocks; this format applies only to the final answer."}, nil
	case "json_schema":
		spec, ok := format["json_schema"].(map[string]interface{})
		if !ok || spec["schema"] == nil {
			return nil, fmt.Errorf("response_format.json_schema.schema is required")
		}
		compiler := jsonschema.NewCompiler()
		compiler.UseLoader(noExternalSchemas{})
		const resource = "https://schema.invalid/response.json"
		if err := compiler.AddResource(resource, spec["schema"]); err != nil {
			return nil, fmt.Errorf("invalid response JSON schema")
		}
		schema, err := compiler.Compile(resource)
		if err != nil {
			return nil, fmt.Errorf("invalid response JSON schema or unsupported external reference")
		}
		encoded, err := json.Marshal(spec["schema"])
		if err != nil {
			return nil, fmt.Errorf("invalid response JSON schema")
		}
		return &outputContract{schema: schema, instruction: "Your final answer MUST be JSON matching the following schema. No markdown fences or prose. Tool calls, when needed, still use tool_call blocks; this schema applies only to the final answer.\n" + string(encoded)}, nil
	default:
		return nil, fmt.Errorf("unsupported response_format type")
	}
}

func (c *outputContract) messages(messages []map[string]interface{}) []map[string]interface{} {
	if c == nil {
		return messages
	}
	// Copy the slice: callers and the continuation history remain unchanged.
	result := make([]map[string]interface{}, 0, len(messages)+1)
	result = append(result, map[string]interface{}{"role": "system", "content": c.instruction})
	return append(result, messages...)
}

func (c *outputContract) validate(text string, calls []ToolCall) (string, error) {
	if c == nil {
		return text, nil
	}
	if len(calls) > 0 {
		return "", nil
	} // A tool turn is not a final structured answer.
	text = strings.TrimSpace(text)
	// Strip only a fence enclosing the entire JSON document, never extract a guessed substring.
	if strings.HasPrefix(text, "```json\n") && strings.HasSuffix(text, "```") {
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "```json\n"), "```"))
	}
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(text))
	if err != nil {
		return "", fmt.Errorf("upstream response did not satisfy response_format: invalid JSON")
	}
	if c.jsonObject {
		if _, ok := value.(map[string]interface{}); !ok {
			return "", fmt.Errorf("upstream response did not satisfy response_format: expected an object")
		}
	}
	if c.schema != nil {
		if err := c.schema.Validate(value); err != nil {
			return "", fmt.Errorf("upstream response did not satisfy the requested JSON schema")
		}
	}
	return text, nil
}
