#!/bin/bash
# ThreatWeaver Sandbox Demo - Quick Launch Script

set -e

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                                                                    ║"
echo "║         ThreatWeaver Sandbox System - Demo Launcher               ║"
echo "║                                                                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in the backend directory
if [ ! -f "run_sandbox_demo.py" ]; then
    echo "❌ ERROR: Please run this script from the backend directory"
    echo ""
    echo "  cd backend"
    echo "  ./demo.sh"
    exit 1
fi

# Set E2B API key
export E2B_API_KEY="e2b_9b7c601537c06efcc44aad5c13fb19fd2d257476"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ ERROR: Virtual environment not found"
    echo ""
    echo "Please set up the environment first:"
    echo "  uv sync"
    exit 1
fi

# Run the demo
echo "🚀 Launching sandbox demo..."
echo ""

.venv/bin/python run_sandbox_demo.py

echo ""
echo "✅ Demo complete!"
