#!/bin/bash
#
# Quick demo script for Subfinder Agent
#
# Usage:
#   ./run_demo.sh                    # Scan google.com
#   ./run_demo.sh hackerone.com      # Scan specific domain
#   ./run_demo.sh example.com 120    # Scan with custom timeout
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Configuration
DOMAIN="${1:-google.com}"
TIMEOUT="${2:-300}"
E2B_KEY="${E2B_API_KEY:-e2b_9b7c601537c06efcc44aad5c13fb19fd2d257476}"

echo -e "${BLUE}🚀 ThreatWeaver Subfinder Demo${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo -e "${RED}❌ Error: uv not found${NC}"
    echo "Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check Python dependencies
echo -e "${YELLOW}📦 Checking dependencies...${NC}"
if [ ! -d ".venv" ]; then
    echo "Installing dependencies (first run only)..."
    uv sync
fi

# Run the demo
echo -e "${GREEN}✨ Starting Subfinder agent demo...${NC}"
echo ""

E2B_API_KEY="$E2B_KEY" uv run python demo_subfinder.py "$DOMAIN" --timeout "$TIMEOUT"

echo ""
echo -e "${GREEN}✅ Demo completed successfully!${NC}"
echo ""
echo -e "${YELLOW}💡 Tips:${NC}"
echo "  • Scan different domain: ./run_demo.sh hackerone.com"
echo "  • Custom timeout: ./run_demo.sh example.com 120"
echo "  • View results: ls -lh nexus-data/demo-team/demo-scan/recon/subfinder/"
echo ""
