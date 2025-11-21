#!/bin/bash
# Run ThreatWeaver Sandbox Demo
# Interactive demo of sandbox execution capabilities

set -e

echo "=========================================="
echo "ThreatWeaver Sandbox Demo"
echo "=========================================="
echo ""

# Check for E2B API key
if [ -z "$E2B_API_KEY" ]; then
    echo "❌ ERROR: E2B_API_KEY not set"
    echo ""
    echo "Please set your E2B API key:"
    echo "  export E2B_API_KEY=e2b_9b7c601537c06efcc44aad5c13fb19fd2d257476"
    echo ""
    exit 1
fi

echo "✅ E2B API Key configured"
echo ""

# Navigate to backend directory
cd "$(dirname "$0")/.."

echo "Running sandbox demo..."
echo ""

.venv/bin/python examples/sandbox_demo.py

echo ""
echo "=========================================="
echo "Demo completed!"
echo "=========================================="
