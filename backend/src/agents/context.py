"""
Agent Context Module.

Provides a simple context mechanism for passing scan_id, team_id, and backend
to tool functions without explicitly passing them as parameters.

This uses a thread-local context pattern similar to Flask's request context.
"""

import threading
from typing import Optional
from dataclasses import dataclass

from agents.backends.nexus_backend import NexusBackend


@dataclass
class AgentContext:
    """Agent execution context."""
    scan_id: str
    team_id: str
    backend: NexusBackend


# Thread-local storage for agent context
_context_storage = threading.local()


def set_agent_context(scan_id: str, team_id: str, backend: NexusBackend) -> None:
    """
    Set the current agent context.

    This should be called before creating agents that use recon tools.

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance

    Example:
        >>> from agents.context import set_agent_context
        >>> set_agent_context("scan-123", "team-abc", backend)
        >>> agent = create_deep_agent(...)  # Tools will use this context
    """
    _context_storage.context = AgentContext(
        scan_id=scan_id,
        team_id=team_id,
        backend=backend
    )


def get_agent_context() -> AgentContext:
    """
    Get the current agent context.

    Tries to dynamically create backend from LangGraph thread_id if not already set.

    Returns:
        AgentContext with scan_id, team_id, and backend

    Raises:
        RuntimeError: If context has not been set and cannot be auto-created
    """
    # First check if context is already set
    if hasattr(_context_storage, 'context'):
        return _context_storage.context

    # Try to auto-create context from LangGraph runtime
    try:
        from langchain_core.runnables.config import var_child_runnable_config
        from config.nexus_config import get_nexus_fs

        config = var_child_runnable_config.get(None)
        if config:
            thread_id = config.get("configurable", {}).get("thread_id")
            if thread_id and thread_id != "placeholder":
                # Auto-create backend for this thread
                team_id = "default-team"
                nexus_fs = get_nexus_fs()
                backend = NexusBackend(thread_id, team_id, nexus_fs)

                # Set and return context
                set_agent_context(thread_id, team_id, backend)

                import structlog
                logger = structlog.get_logger()
                logger.info(f"🔧 Auto-created backend: thread_id={thread_id[:12]}..., team={team_id}")
                logger.info(f"   Storage: gs://bucket/{team_id}/{thread_id}/")

                return _context_storage.context
    except Exception as e:
        pass  # Fall through to error

    raise RuntimeError(
        "Agent context not set. Call set_agent_context() before using recon tools."
    )


def clear_agent_context() -> None:
    """Clear the current agent context."""
    if hasattr(_context_storage, 'context'):
        delattr(_context_storage, 'context')
