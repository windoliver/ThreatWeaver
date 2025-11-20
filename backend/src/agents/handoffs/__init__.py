"""
Hybrid Agent Handoff System.

This module implements the hybrid handoff architecture that balances speed (in-memory)
with persistence (historical context). It provides:

- TypedDict schemas for type-safe handoff contracts
- HandoffPersistence for saving/loading handoffs to/from Nexus
- Handoff analysis nodes for LangGraph workflows
- Diff detection for cross-scan comparisons

Architecture:
- Layer 1: In-memory handoffs (LangGraph state) - fast, ephemeral
- Layer 2: Persistent handoffs (Nexus workspace) - historical context

Reference:
- architecture.md Section 4 (Hybrid Agent Handoff Architecture)
"""

from src.agents.handoffs.diff import DiffDetector, HandoffDiff
from src.agents.handoffs.nodes import (
    assessment_to_exploit_handoff,
    finalize_scan,
    recon_to_assessment_handoff,
)
from src.agents.handoffs.persistence import HandoffPersistence
from src.agents.handoffs.schemas import (
    AssessmentHandoff,
    ReconHandoff,
    ScanState,
)

__all__ = [
    # Schemas
    "ReconHandoff",
    "AssessmentHandoff",
    "ScanState",
    # Persistence
    "HandoffPersistence",
    # Nodes
    "recon_to_assessment_handoff",
    "assessment_to_exploit_handoff",
    "finalize_scan",
    # Diff detection
    "DiffDetector",
    "HandoffDiff",
]
