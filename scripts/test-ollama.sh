#!/bin/bash
OLLAMA_URL=${1:-http://localhost:11434}
MODEL=${2:-gpt-oss:20b}

echo "Testing Ollama at $OLLAMA_URL with model $MODEL..."
echo ""

# Check server reachability and list models
curl -s "$OLLAMA_URL/api/tags" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    models = [m['name'] for m in data.get('models', [])]
    print('Available models:', models)
    model = '$MODEL'
    found = model in models or any(m.startswith(model) for m in models)
    if found:
        print(f'Model found: {model}')
    else:
        print(f'WARNING: model {model} not found in available models')
        sys.exit(1)
except json.JSONDecodeError:
    print('ERROR: Could not parse Ollama response. Is Ollama running at $OLLAMA_URL?')
    sys.exit(1)
"
