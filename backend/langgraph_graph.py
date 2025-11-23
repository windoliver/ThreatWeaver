"""
LangGraph graph factory for Recon Coordinator.

This module provides a LangGraph Studio compatible entry point
for the Recon Coordinator agent.

Following Syntar's pattern: Build graph ONCE at module load time for fast schema access.
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

from agents.backends.nexus_backend import NexusBackend
from agents.recon_coordinator import create_recon_coordinator  # DeepAgents version!
from config.nexus_config import get_nexus_fs

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

logger.info("=" * 80)
logger.info("🔍 RECON COORDINATOR LANGGRAPH AGENT INITIALIZATION")
logger.info("=" * 80)

# Create default backend for LangGraph Studio (schema loading)
# Runtime backend creation - use thread_id as scan_id
logger.info("🔨 Preparing backend factory (per-thread isolation)...")
DEFAULT_TEAM_ID = "default-team"

try:
    nexus_fs = get_nexus_fs()
    logger.info("✅ NexusFS initialized")
except Exception as e:
    logger.warning(f"⚠️  Could not initialize NexusFS: {e}")
    nexus_fs = None

# Create model
logger.info("🤖 Creating LLM model...")
openrouter_key = os.getenv("OPENROUTER_API_KEY")
if not openrouter_key:
    raise ValueError("OPENROUTER_API_KEY not set in environment")

model = ChatOpenAI(
    model="anthropic/claude-3.5-sonnet",
    api_key=openrouter_key,  # Use api_key param (not openai_api_key)
    base_url="https://openrouter.ai/api/v1",  # Use base_url (not openai_api_base)
    temperature=0
)
logger.info("✅ Model created")

# Create wrapper that creates per-thread backend
logger.info("🔨 Creating Recon Coordinator with DeepAgents (per-thread isolation)...")

# For per-thread isolation, we need to monkey-patch the tool execution
# to dynamically set up the backend based on thread_id from config
from agents.context import set_agent_context

# Create a global hook that sets up backend before each tool call
original_context_get = None

def setup_dynamic_context():
    """Setup dynamic context extraction from LangGraph runtime"""
    import contextvars
    from langchain_core.runnables.config import var_child_runnable_config

    global original_context_get

    def get_dynamic_backend():
        """Extract thread_id from LangGraph context and create backend"""
        try:
            # Try to get config from LangChain context
            config = var_child_runnable_config.get()
            if config:
                thread_id = config.get("configurable", {}).get("thread_id")
                if thread_id and thread_id != "placeholder":
                    # Create backend for this thread
                    backend = NexusBackend(thread_id, DEFAULT_TEAM_ID, nexus_fs)
                    set_agent_context(thread_id, DEFAULT_TEAM_ID, backend)
                    logger.info(f"🔧 Dynamic backend: thread={thread_id[:12]}...")
                    return True
        except Exception as e:
            logger.debug(f"Could not extract thread_id from context: {e}")

        return False

    return get_dynamic_backend

# Setup dynamic context
dynamic_backend_getter = setup_dynamic_context()

try:
    if nexus_fs:
        # Create coordinator with placeholder - context will be set dynamically
        agent = create_recon_coordinator(
            scan_id="placeholder",
            team_id=DEFAULT_TEAM_ID,
            backend=None,
            model=model
        )

        # Patch the graph to setup backend before execution
        original_invoke = agent.invoke

        def invoke_with_dynamic_backend(input_data, config=None):
            # Extract thread_id and setup backend
            config = config or {}
            thread_id = config.get("configurable", {}).get("thread_id", "default-thread")

            # Create backend for this thread
            backend = NexusBackend(thread_id, DEFAULT_TEAM_ID, nexus_fs)
            set_agent_context(thread_id, DEFAULT_TEAM_ID, backend)

            logger.info(f"🔧 Thread: {thread_id[:12]}... → gs://bucket/{DEFAULT_TEAM_ID}/{thread_id}/")

            # Call original invoke
            return original_invoke(input_data, config)

        agent.invoke = invoke_with_dynamic_backend

        logger.info("✅ Graph created with per-thread backend isolation")
    else:
        # Fallback: create without backend (will fail at runtime but schema loads fast)
        logger.warning("⚠️  Creating graph without backend - runtime execution may fail")
        agent = create_recon_coordinator("placeholder", DEFAULT_TEAM_ID, None, model)
except Exception as e:
    logger.error(f"❌ Failed to create graph: {e}", exc_info=True)
    raise

logger.info("=" * 80)
logger.info("✅ RECON COORDINATOR AGENT READY (Per-Thread Isolation)")
logger.info("=" * 80)
logger.info("")
logger.info("📊 Each thread gets its own scan_id:")
logger.info('   Thread ID → Scan ID → gs://bucket/{team_id}/{thread_id}/')
logger.info("")

# Export for LangGraph (module-level variable = fast schema loading!)
# Graph built once, backend created per-thread at runtime
