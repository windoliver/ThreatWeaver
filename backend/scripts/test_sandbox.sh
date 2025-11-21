#!/bin/bash
# ThreatWeaver Sandbox Test Script
# Tests E2B sandbox provider with security tools

set -e  # Exit on error

echo "=========================================="
echo "ThreatWeaver Sandbox System Tests"
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

echo "✅ E2B API Key: ${E2B_API_KEY:0:10}..."
echo ""

# Navigate to backend directory
cd "$(dirname "$0")/.."

echo "=========================================="
echo "Step 1: Configuration Tests"
echo "=========================================="
echo ""

.venv/bin/pytest tests/test_sandbox.py::TestSandboxConfig -v --tb=short

echo ""
echo "=========================================="
echo "Step 2: Factory Tests"
echo "=========================================="
echo ""

.venv/bin/pytest tests/test_sandbox.py::TestSandboxFactory -v --tb=short

echo ""
echo "=========================================="
echo "Step 3: E2B Provider Tests"
echo "=========================================="
echo ""

.venv/bin/pytest tests/test_sandbox.py::TestE2BSandboxProvider -v --tb=short -s

echo ""
echo "=========================================="
echo "Step 4: Security Tool Tests"
echo "=========================================="
echo ""

.venv/bin/pytest tests/test_sandbox.py::TestSecurityToolExecution -v --tb=short

echo ""
echo "=========================================="
echo "✅ All tests completed!"
echo "=========================================="
echo ""

# Test summary
echo "Test Summary:"
echo "  - Configuration: ✅"
echo "  - Factory: ✅"
echo "  - E2B Provider: ✅"
echo "  - Security Tools: ✅"
echo ""
echo "Sandbox system is ready for production! 🚀"
