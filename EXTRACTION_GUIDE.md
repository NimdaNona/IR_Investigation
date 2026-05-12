# Advanced Extraction Guide

Techniques for extracting specific data from Claude Code session files.

## Finding Sessions

### List all project folders
```bash
ls ~/.claude/projects/
```

### Find sessions by project name
```bash
ls ~/.claude/projects/ | grep -i "projectname"
```

### Find session by ID (partial match)
```bash
find ~/.claude/projects -name "*19491ae8*" -type f
```

### Find recently modified sessions
```bash
find ~/.claude/projects -name "*.jsonl" -mtime -1 -type f
```

### Find largest sessions (most content)
```bash
find ~/.claude/projects -name "*.jsonl" -type f -exec ls -la {} \; | sort -k5 -n -r | head -10
```

## Extracting User Prompts

### All prompts (simple text only)
```bash
grep '"type":"user"' FILE.jsonl | \
  jq -r 'select(.message.content | type == "string") | .message.content' 2>/dev/null
```

### Prompts with timestamps
```bash
grep '"type":"user"' FILE.jsonl | \
  jq -r 'select(.message.content | type == "string") | "[\(.timestamp)] \(.message.content)"' 2>/dev/null
```

### First N prompts
```bash
grep '"type":"user"' FILE.jsonl | head -N | \
  jq -r 'select(.message.content | type == "string") | .message.content' 2>/dev/null
```

### Prompts containing keyword
```bash
grep '"type":"user"' FILE.jsonl | grep -i "keyword" | \
  jq -r '.message.content' 2>/dev/null
```

## Extracting Claude Responses

### All text responses
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="text") | .text' 2>/dev/null
```

### Responses with message IDs
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '"\(.uuid): \(.message.content[]? | select(.type=="text") | .text)"' 2>/dev/null
```

### Short summary of each response (first 200 chars)
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="text") | .text[:200]' 2>/dev/null
```

## Extracting Thinking Blocks

### All thinking content
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="thinking") | .thinking' 2>/dev/null
```

### Thinking with timestamps
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '(.message.content[]? | select(.type=="thinking")) as $t | "[\(.timestamp)] \($t.thinking)"' 2>/dev/null
```

## Extracting Tool Usage

### List all tool calls
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="tool_use") | .name' 2>/dev/null | sort | uniq -c | sort -rn
```

### Tool calls with inputs
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="tool_use") | "\(.name): \(.input | tostring[:100])"' 2>/dev/null
```

### Specific tool usage (e.g., Read)
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="tool_use" and .name=="Read") | .input.file_path' 2>/dev/null
```

### Bash commands executed
```bash
grep '"type":"assistant"' FILE.jsonl | \
  jq -r '.message.content[]? | select(.type=="tool_use" and .name=="Bash") | .input.command' 2>/dev/null
```

## Extracting Tool Results

### All tool results
```bash
grep '"type":"user"' FILE.jsonl | grep "tool_result" | \
  jq -r '.toolUseResult.stdout // .message.content[0].content' 2>/dev/null
```

### Tool errors
```bash
grep '"type":"user"' FILE.jsonl | grep '"is_error":true' | \
  jq -r '.message.content[0].content' 2>/dev/null
```

## Session Metadata

### Get session info
```bash
head -5 FILE.jsonl | jq -s '.[0] | {sessionId, cwd, version, gitBranch, timestamp}' 2>/dev/null
```

### Get model used
```bash
grep '"type":"assistant"' FILE.jsonl | head -1 | jq -r '.message.model' 2>/dev/null
```

### Count messages by type
```bash
jq -r '.type' FILE.jsonl 2>/dev/null | sort | uniq -c
```

### Session duration
```bash
echo "Start: $(head -1 FILE.jsonl | jq -r '.timestamp')"
echo "End: $(tail -1 FILE.jsonl | jq -r '.timestamp')"
```

## Full Conversation Reconstruction

### Chronological conversation (prompts and responses)
```bash
grep -E '"type":"(user|assistant)"' FILE.jsonl | \
  jq -r '
    if .type == "user" then
      if .message.content | type == "string" then
        "\n=== USER ===\n\(.message.content)"
      else
        empty
      end
    else
      (.message.content[]? | select(.type=="text") | "\n=== CLAUDE ===\n\(.text)") // empty
    end
  ' 2>/dev/null
```

### Conversation with timestamps
```bash
grep -E '"type":"(user|assistant)"' FILE.jsonl | \
  jq -r '
    .timestamp as $ts |
    if .type == "user" then
      if .message.content | type == "string" then
        "\n[\($ts)] USER:\n\(.message.content)"
      else
        empty
      end
    else
      (.message.content[]? | select(.type=="text") | "\n[\($ts)] CLAUDE:\n\(.text)") // empty
    end
  ' 2>/dev/null
```

## Searching Across Sessions

### Find sessions mentioning a keyword
```bash
grep -l "keyword" ~/.claude/projects/*/*.jsonl 2>/dev/null
```

### Search all user prompts for a term
```bash
for f in ~/.claude/projects/*/*.jsonl; do
  if grep -q '"type":"user"' "$f" && grep -i "keyword" "$f" >/dev/null 2>&1; then
    echo "=== $f ==="
    grep '"type":"user"' "$f" | grep -i "keyword" | jq -r '.message.content' 2>/dev/null
  fi
done
```

### Find sessions by date
```bash
find ~/.claude/projects -name "*.jsonl" -type f | while read f; do
  timestamp=$(head -1 "$f" | jq -r '.timestamp' 2>/dev/null)
  if [[ "$timestamp" == 2025-11-22* ]]; then
    echo "$f"
  fi
done
```

## Working with Large Files

### Stream processing (memory efficient)
```bash
# Process line by line
while IFS= read -r line; do
  echo "$line" | jq -r 'select(.type=="user") | .message.content' 2>/dev/null
done < FILE.jsonl
```

### Sample entries
```bash
# Every 10th entry
awk 'NR % 10 == 0' FILE.jsonl | jq '.type' 2>/dev/null
```

### Last N messages
```bash
tail -20 FILE.jsonl | grep -E '"type":"(user|assistant)"' | jq -r '.type, .message.content[:100]' 2>/dev/null
```

## Exporting Data

### Export prompts to text file
```bash
grep '"type":"user"' FILE.jsonl | \
  jq -r 'select(.message.content | type == "string") | .message.content' > prompts.txt 2>/dev/null
```

### Export as CSV
```bash
grep '"type":"user"' FILE.jsonl | \
  jq -r 'select(.message.content | type == "string") | [.timestamp, .uuid, .message.content] | @csv' 2>/dev/null > messages.csv
```

### Export conversation as markdown
```bash
echo "# Session Conversation" > conversation.md
grep -E '"type":"(user|assistant)"' FILE.jsonl | \
  jq -r '
    if .type == "user" then
      if .message.content | type == "string" then
        "## User\n\(.message.content)\n"
      else empty end
    else
      (.message.content[]? | select(.type=="text") | "## Claude\n\(.text)\n") // empty
    end
  ' >> conversation.md 2>/dev/null
```

## Troubleshooting

### Check file validity
```bash
head -1 FILE.jsonl | jq '.' >/dev/null && echo "Valid JSON" || echo "Invalid JSON"
```

### Count valid entries
```bash
jq -c '.' FILE.jsonl 2>/dev/null | wc -l
```

### Find malformed lines
```bash
awk '{if(system("echo \047"$0"\047 | jq . >/dev/null 2>&1") != 0) print NR": "$0}' FILE.jsonl
```
