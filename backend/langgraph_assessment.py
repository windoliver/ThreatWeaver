"""
LangGraph graph factory for Assessment Coordinator.

This module provides a LangGraph Studio compatible entry point
for the Assessment Coordinator agent (Nuclei + SQLMap orchestration).

Following Syntar's pattern: Build graph ONCE at module load time for fast schema access.

The tools (run_nuclei, run_sqlmap) automatically extract thread_id from
LangGraph's RunnableConfig and create their own backend - no manual binding needed.
"""

import logging
import os
import sys
from pathlib import Path

# Load .env file explicitly (LangGraph loads it but we need it at module time)
from dotenv import load_dotenv
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

# Add src to path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from langchain_openai import ChatOpenAI

from src.agents.assessment_coordinator import create_assessment_coordinator

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

logger.info("=" * 80)
logger.info("🔒 ASSESSMENT COORDINATOR LANGGRAPH AGENT INITIALIZATION")
logger.info("=" * 80)

# Create model
logger.info("🤖 Creating LLM model (Claude Sonnet 4)...")
openrouter_key = os.getenv("OPENROUTER_API_KEY")
if not openrouter_key:
    raise ValueError("OPENROUTER_API_KEY not set in environment")

model = ChatOpenAI(
    model="anthropic/claude-sonnet-4",
    api_key=openrouter_key,
    base_url="https://openrouter.ai/api/v1",
    temperature=0
)
logger.info("✅ Model created")

# Create coordinator
logger.info("🔨 Creating Assessment Coordinator with DeepAgents...")

try:
    # Create coordinator - tools auto-extract thread_id from LangGraph config
    # and create their own backend with per-thread isolation
    agent = create_assessment_coordinator(
        scan_id="placeholder",  # Will be overridden by thread_id in tools
        team_id="default-team",
        backend=None,  # Tools create their own backend from config
        model=model
    )
    logger.info("✅ Assessment Coordinator ready")
except Exception as e:
    logger.error(f"❌ Failed to create graph: {e}", exc_info=True)
    raise

logger.info("=" * 80)
logger.info("✅ ASSESSMENT COORDINATOR READY")
logger.info("=" * 80)
logger.info("")
logger.info("🔒 Assessment Tools:")
logger.info("   - Nuclei: Template-based vulnerability scanning")
logger.info("   - SQLMap: SQL injection testing (requires approval)")
logger.info("")
logger.info("📋 Workflow:")
logger.info("   1. Nuclei scan → Find vulnerabilities")
logger.info("   2. SQLi detection → Conditional escalation")
logger.info("   3. HITL approval → For exploitation")
logger.info("   4. SQLMap → Deep SQLi testing")
logger.info("")
logger.info("📝 Note: Tools auto-extract thread_id from LangGraph config")
logger.info("   Storage: gs://bucket/{team_id}/{thread_id}/assessment/")
logger.info("")

# Export for LangGraph (module-level variable = fast schema loading!)
