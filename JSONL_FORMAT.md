# Claude Code JSONL Format Specification

Complete reference for the Claude Code session file format.

## File Structure

Each `.jsonl` file contains one JSON object per line. Lines are appended as the conversation progresses.

## Directory Structure

```
~/.claude/projects/
├── -Users-sterlingclifton-Projects-cliftonsites/  # Project folder (path with dashes)
│   ├── 19491ae8-3774-...jsonl       # Main session file
│   ├── agent-db224b6e.jsonl         # Subagent session
│   └── agent-38bdca08.jsonl         # Another subagent
├── -home-user-code/
│   └── ...
└── ...
```

## Entry Types

### 1. User Message Entry

```json
{
  "parentUuid": "previous-message-uuid",
  "isSidechain": false,
  "userType": "external",
  "cwd": "/mnt/c/Projects/myapp",
  "sessionId": "19491ae8-3774-4555-87b5-3f6f9725e4b4",
  "version": "2.0.50",
  "gitBranch": "main",
  "type": "user",
  "message": {
    "role": "user",
    "content": "User's prompt text here"
  },
  "uuid": "f354b4e2-9ad8-4c30-b069-019e6b2c06e2",
  "timestamp": "2025-11-22T12:10:25.227Z",
  "thinkingMetadata": {
    "level": "high",
    "disabled": false,
    "triggers": []
  },
  "todos": []
}
```

### 2. User Message with Tool Result

When Claude used a tool, the result comes back as a user message:

```json
{
  "parentUuid": "tool-use-message-uuid",
  "isSidechain": false,
  "userType": "external",
  "cwd": "/mnt/c",
  "sessionId": "19491ae8-3774-4555-87b5-3f6f9725e4b4",
  "version": "2.0.50",
  "gitBranch": "",
  "type": "user",
  "message": {
    "role": "user",
    "content": [
      {
        "tool_use_id": "toolu_0137dkk1i2toqHkBPr6FwhYd",
        "type": "tool_result",
        "content": "Python 3.12.3",
        "is_error": false
      }
    ]
  },
  "uuid": "936b88e5-fef3-48d7-9097-9569b82301a0",
  "timestamp": "2025-11-22T12:10:31.858Z",
  "toolUseResult": {
    "stdout": "Python 3.12.3",
    "stderr": "",
    "interrupted": false,
    "isImage": false
  }
}
```

### 3. Assistant Message Entry

```json
{
  "parentUuid": "user-message-uuid",
  "isSidechain": false,
  "userType": "external",
  "cwd": "/mnt/c",
  "sessionId": "19491ae8-3774-4555-87b5-3f6f9725e4b4",
  "version": "2.0.50",
  "gitBranch": "",
  "message": {
    "model": "claude-sonnet-4-5-20250929",
    "id": "msg_01Jo49ozz6CqKAAVGhfAUoym",
    "type": "message",
    "role": "assistant",
    "content": [
      {
        "type": "text",
        "text": "Claude's response text here"
      }
    ],
    "stop_reason": "end_turn",
    "stop_sequence": null,
    "usage": {
      "input_tokens": 1234,
      "output_tokens": 567,
      "cache_creation_input_tokens": 0,
      "cache_read_input_tokens": 0
    }
  },
  "requestId": "req_011CVNuQ9Ba3STp5hxYFFeXj",
  "type": "assistant",
  "uuid": "db6e71eb-9817-491e-b08d-59b1a3dd6646",
  "timestamp": "2025-11-22T12:10:28.365Z"
}
```

### 4. Assistant Message with Thinking

```json
{
  "message": {
    "content": [
      {
        "type": "thinking",
        "thinking": "Let me analyze this request...\n\nThe user wants to...",
        "signature": "base64-encoded-signature..."
      },
      {
        "type": "text",
        "text": "Visible response to user"
      }
    ]
  }
}
```

### 5. Assistant Message with Tool Use

```json
{
  "message": {
    "content": [
      {
        "type": "tool_use",
        "id": "toolu_01Mp3YhNrjxma3rRJ7CUDayv",
        "name": "WebFetch",
        "input": {
          "url": "https://example.com",
          "prompt": "Extract relevant information"
        }
      }
    ]
  }
}
```

### 6. File History Snapshot

Internal bookkeeping entry (skip when parsing conversations):

```json
{
  "type": "file-history-snapshot",
  "messageId": "f354b4e2-9ad8-4c30-b069-019e6b2c06e2",
  "snapshot": {
    "messageId": "f354b4e2-9ad8-4c30-b069-019e6b2c06e2",
    "trackedFileBackups": {},
    "timestamp": "2025-11-22T12:10:25.246Z"
  },
  "isSnapshotUpdate": false
}
```

### 7. Agent Session Entry

Subagent sessions have an `agentId` field:

```json
{
  "parentUuid": null,
  "isSidechain": true,
  "userType": "external",
  "cwd": "/mnt/c",
  "sessionId": "19491ae8-3774-4555-87b5-3f6f9725e4b4",
  "version": "2.0.50",
  "gitBranch": "",
  "agentId": "db224b6e",
  "message": {...},
  "type": "assistant",
  "uuid": "...",
  "timestamp": "..."
}
```

## Field Reference

### Core Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Entry type: "user", "assistant", "file-history-snapshot" |
| `uuid` | string | Unique identifier for this entry |
| `parentUuid` | string\|null | UUID of the previous message in conversation |
| `sessionId` | string | Session identifier (shared across all entries in session) |
| `timestamp` | string | ISO 8601 timestamp |

### Context Fields

| Field | Type | Description |
|-------|------|-------------|
| `cwd` | string | Working directory |
| `version` | string | Claude Code version (e.g., "2.0.50") |
| `gitBranch` | string | Current git branch (empty if not in repo) |
| `isSidechain` | boolean | True for side conversations/agents |
| `userType` | string | Usually "external" |
| `agentId` | string | Present only for subagent sessions |

### Message Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `message.role` | string | "user" or "assistant" |
| `message.content` | string\|array | Message content (see Content Types) |
| `message.model` | string | Model identifier (assistant only) |
| `message.id` | string | Anthropic message ID (assistant only) |
| `message.usage` | object | Token usage stats (assistant only) |

### Content Block Types

| Type | Fields | Description |
|------|--------|-------------|
| `text` | `text` | Plain text response |
| `thinking` | `thinking`, `signature` | Internal reasoning (extended thinking) |
| `tool_use` | `id`, `name`, `input` | Tool invocation |
| `tool_result` | `tool_use_id`, `content`, `is_error` | Tool execution result |

### Tool Result Fields

The `toolUseResult` field contains:

| Field | Type | Description |
|-------|------|-------------|
| `stdout` | string | Standard output |
| `stderr` | string | Standard error |
| `interrupted` | boolean | Whether execution was interrupted |
| `isImage` | boolean | Whether result is an image |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `todos` | array | Task list from TodoWrite tool |
| `thinkingMetadata` | object | Thinking level settings |
| `requestId` | string | API request identifier |

## Model Identifiers

Common model values in `message.model`:

- `claude-sonnet-4-5-20250929` - Claude Sonnet 4.5
- `claude-opus-4-5-20251101` - Claude Opus 4.5
- `claude-haiku-4-5-20251001` - Claude Haiku 4.5

## Timestamps

All timestamps are ISO 8601 format in UTC:
```
2025-11-22T12:10:25.227Z
```

## Conversation Threading

Messages form a linked list via `parentUuid`:

```
null ← uuid1 ← uuid2 ← uuid3 ← uuid4
      (user)  (asst)  (user)  (asst)
```

To reconstruct conversation order, follow `parentUuid` links or sort by `timestamp`.
