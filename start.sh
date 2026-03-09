#!/bin/bash
echo ""
echo "🛡️  PromptShield Firewall — Starting..."
echo ""

# Check API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "❌  ERROR: ANTHROPIC_API_KEY not set."
  echo "    Run: export ANTHROPIC_API_KEY=sk-ant-..."
  exit 1
fi

# Install dependencies if needed
pip install -r requirements.txt -q

echo "✅  Dependencies ready"
echo "✅  API key found"
echo ""
echo "🚀  Starting server at http://localhost:8000"
echo "📋  Open index.html in your browser"
echo ""

uvicorn app:app --reload --port 8000
