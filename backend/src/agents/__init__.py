"""ThreatWeaver Security Agents.

This package provides DeepAgents-based security agents for reconnaissance,
vulnerability assessment, and exploitation workflows.
"""

# Import handoffs (always available)
from src.agents.handoffs import (
    AssessmentHandoff,
    DiffDetector,
    HandoffDiff,
    HandoffPersistence,
    ReconHandoff,
    ScanState,
    assessment_to_exploit_handoff,
    finalize_scan,
    recon_to_assessment_handoff,
)

# Import agent factory and backends (may not be available if deepagents not installed)
try:
    from src.agents.backends import NexusBackend
    from src.agents.agent_factory import (
        create_assessment_supervisor,
        create_httpx_agent,
        create_nmap_agent,
        create_nuclei_agent,
        create_recon_coordinator,
        create_security_agent,
        create_sqlmap_agent,
        create_subfinder_agent,
    )

    _DEEPAGENTS_AVAILABLE = True
except ImportError:
    _DEEPAGENTS_AVAILABLE = False

    # Provide stub for NexusBackend
    class NexusBackend:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "NexusBackend requires 'deepagents' package. "
                "Install with: uv add deepagents"
            )

    # Provide stub functions that raise helpful errors
    def _create_unavailable_factory(name):
        def _stub(*args, **kwargs):
            raise ImportError(
                f"{name} requires 'deepagents' package. "
                "Install with: uv add deepagents"
            )

        return _stub

    create_security_agent = _create_unavailable_factory("create_security_agent")
    create_subfinder_agent = _create_unavailable_factory("create_subfinder_agent")
    create_httpx_agent = _create_unavailable_factory("create_httpx_agent")
    create_nmap_agent = _create_unavailable_factory("create_nmap_agent")
    create_nuclei_agent = _create_unavailable_factory("create_nuclei_agent")
    create_sqlmap_agent = _create_unavailable_factory("create_sqlmap_agent")
    create_recon_coordinator = _create_unavailable_factory("create_recon_coordinator")
    create_assessment_supervisor = _create_unavailable_factory("create_assessment_supervisor")

__all__ = [
    # Backends
    "NexusBackend",
    # Factory functions
    "create_security_agent",
    # ReconEngine agents
    "create_subfinder_agent",
    "create_httpx_agent",
    "create_nmap_agent",
    # AssessmentEngine agents
    "create_nuclei_agent",
    "create_sqlmap_agent",
    # Coordinators
    "create_recon_coordinator",
    "create_assessment_supervisor",
    # Handoffs
    "ReconHandoff",
    "AssessmentHandoff",
    "ScanState",
    "HandoffPersistence",
    "DiffDetector",
    "HandoffDiff",
    "recon_to_assessment_handoff",
    "assessment_to_exploit_handoff",
    "finalize_scan",
]
