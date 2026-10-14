# Chat Completions agent output contracts

`/v1/chat/completions` (also under a configured API prefix such as `/google`)
now handles `response_format: {type: "json_object"}` and
`{type: "json_schema", json_schema: {name, schema, strict}}`.

The proxy sends the schema as an instruction to Gemini and validates the final
answer against it. This is not native constrained decoding: the upstream may
still produce a nonconforming answer. That produces HTTP 502, or an SSE error
if reasoning already started streaming, instead of a successful but unparseable
agent result. No automatic regeneration is performed. Local `$defs`/`$ref` work;
external/file schema references are rejected without fetching them.

For these requests, final-answer content is buffered until validation succeeds.
Reasoning events can still stream. Tool-call turns bypass final-answer schema
validation, retain their call IDs and use the normal client-executed function
calling protocol. A complete enclosing `json` fence can be stripped; arbitrary
prose is not converted or guessed into an answer.

`parallel_tool_calls: true` permits several independent calls in one turn.
False/omitted retains the previous single-call policy. Returning several calls
when it is disabled produces an error, not silently dropped calls. Each call
has its own ID and stream index, and SDK tool results without a `name` are
associated using `tool_call_id`. Dependent calls must wait for their inputs.

Tool and structured-output requests replay the client's conversation history,
so the web conversation cache cannot reuse state with stale tool definitions,
call IDs or output contracts. Ordinary text-only conversations retain caching.

These additions concern Chat Completions. The separate Responses implementation
has not acquired JSON-schema output support in this change. Generation controls
that the web upstream cannot enforce, including output token ceilings, remain
subject to the documented upstream limitations.

Validation: offline Go tests exercise valid/invalid schema results, local versus
external references, SDK-style tool history, serial/parallel contracts, streamed
and nonstreamed responses and errors after streaming starts. No account cookies
or paid upstream requests are needed for these regression tests.
