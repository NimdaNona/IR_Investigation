---
name: claude-session-reader
description: Read and analyze Claude Code session history from JSONL files. Use when asked to review previous Claude Code sessions, find past conversations, extract prompts or responses from session history, understand what was done in a previous session, or when a session ID is provided. Also use when user mentions "previous session", "past conversation", "session history", or wants context from earlier Claude Code work.
---

# Claude Code Session Reader

Read and analyze conversation history from Claude Code sessions stored in JSONL files.

## Session File Location

All Claude Code sessions are stored at:
```
~/.claude/projects/{project-folder}/{session-files}.jsonl
```

**Project folders** are named after the working directory path with slashes replaced by dashes:
- `/Users/sterlingclifton/Projects/cliftonsites` → `-Users-sterlingclifton-Projects-cliftonsites`
- `/home/user/code` → `-home-user-code`

**Session files** have two naming patterns:
- `{uuid}.jsonl` - Main session files (e.g., `19491ae8-3774-4555-87b5-3f6f9725e4b4.jsonl`)
- `agent-{id}.jsonl` - Subagent sessions (e.g., `agent-db224b6e.jsonl`)

## Quick Start

### Find all sessions for a project
```bash
ls ~/.claude/projects/ | grep -i "projectname"
ls ~/.claude/projects/-Users-sterlingclifton-Projects-cliftonsites/
```

### Find a session by ID
```bash
find ~/.claude/projects -name "*SESSION_ID*" -type f
```

### Extract user prompts from a session
```bash
grep '"type":"user"' SESSION_FILE.jsonl | jq -r '.message.content // .message.content[0].content' 2>/dev/null
```

### Extract Claude responses from a session
```bash
grep '"type":"assistant"' SESSION_FILE.jsonl | jq -r '.message.content[] | select(.type=="text") | .text' 2>/dev/null
```

## JSONL Entry Types

Each line in a JSONL file is a separate JSON object. Key entry types:

| Type | Description |
|------|-------------|
| `"type": "user"` | User messages/prompts |
| `"type": "assistant"` | Claude's responses |
| `"type": "file-history-snapshot"` | File state snapshots (skip these) |

## Key Fields Reference

**Core identification:**
- `sessionId` - Unique session identifier (UUID)
- `uuid` - Unique message identifier
- `parentUuid` - Links to previous message (for threading)
- `timestamp` - ISO timestamp of the message

**Context:**
- `cwd` - Working directory for this session
- `version` - Claude Code version
- `gitBranch` - Git branch (if applicable)
- `agentId` - Present for subagent sessions

**Message content:**
- `message.role` - "user" or "assistant"
- `message.content` - The actual content (see format below)
- `message.model` - Model used (e.g., "claude-sonnet-4-5-20250929")

## Message Content Format

### User messages
```json
{
  "type": "user",
  "message": {
    "role": "user",
    "content": "Plain text prompt here"
  }
}
```

Or with tool results:
```json
{
  "type": "user",
  "message": {
    "content": [{"type": "tool_result", "tool_use_id": "...", "content": "result"}]
  },
  "toolUseResult": {"stdout": "...", "stderr": "..."}
}
```

### Assistant messages
Content is an array with different block types:

```json
{
  "type": "assistant",
  "message": {
    "content": [
      {"type": "text", "text": "Response text"},
      {"type": "thinking", "thinking": "Internal reasoning..."},
      {"type": "tool_use", "name": "Read", "input": {"file_path": "/path"}}
    ]
  }
}
```

## Common Extraction Patterns

### Get all user prompts (just text)
```bash
grep '"type":"user"' FILE.jsonl | \
  jq -r 'if .message.content | type == "string" then .message.content else empty end' 2>/dev/null
```

### Get Claude's text responses
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="text") | .text' 2>/dev/null
```

### Get thinking blocks
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="thinking") | .thinking' 2>/dev/null
```

### Get tool calls
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="tool_use") | "\(.name): \(.input)"' 2>/dev/null
```

### Get session metadata
```bash
head -5 FILE.jsonl | jq '{sessionId, cwd, version, gitBranch, timestamp}' 2>/dev/null
```

## Workflow: Reviewing a Previous Session

1. **Locate the session file:**
   ```bash
   # If you have the session ID
   find ~/.claude/projects -name "*SESSION_ID*.jsonl"

   # Or browse project folders
   ls ~/.claude/projects/
   ```

2. **Get session overview:**
   ```bash
   head -3 SESSION.jsonl | jq '{sessionId, cwd, timestamp}'
   wc -l SESSION.jsonl  # Total entries
   grep -c '"type":"user"' SESSION.jsonl  # User message count
   ```

3. **Extract the conversation:**
   ```bash
   # Simple: Just user prompts
   grep '"type":"user"' SESSION.jsonl | jq -r '.message.content' 2>/dev/null | head -20

   # Detailed: Prompts with timestamps
   grep '"type":"user"' SESSION.jsonl | jq -r '"\(.timestamp): \(.message.content)"' 2>/dev/null
   ```

4. **Find specific content:**
   ```bash
   grep -i "keyword" SESSION.jsonl | jq '.message.content' 2>/dev/null
   ```

## Advanced: Full Conversation Reconstruction

For complete conversation with timestamps:

```bash
grep -E '"type":"(user|assistant)"' SESSION.jsonl | \
  jq -r '
    .timestamp as $ts |
    .type as $type |
    if $type == "user" then
      if .message.content | type == "string" then
        "[\($ts)] USER: \(.message.content)"
      else
        empty
      end
    else
      .message.content[]? | select(.type=="text") | "[\($ts)] CLAUDE: \(.text)"
    end
  ' 2>/dev/null
```

## Tips

- **Large files**: Use `head -N` or `tail -N` to limit output
- **File not found**: Check exact project folder name with `ls ~/.claude/projects/`
- **jq errors**: Some entries may have different structures; use `2>/dev/null`
- **Subagents**: Agent files (`agent-*.jsonl`) contain subagent conversations spawned during a session

## Detailed References

- For complete JSONL format specification: See [JSONL_FORMAT.md](JSONL_FORMAT.md)
- For advanced extraction techniques: See [EXTRACTION_GUIDE.md](EXTRACTION_GUIDE.md)
