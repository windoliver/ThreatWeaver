"""
Recon Coordinator - LangGraph-based orchestration of reconnaissance agents.

This module implements Issue #16: Create Recon Coordinator (LangGraph).

The ReconCoordinator is a DeepAgent that orchestrates the complete reconnaissance
workflow by spawning and coordinating sub-agents (Subfinder, HTTPx, Nmap).

Architecture:
- Uses LangChain's DeepAgents framework
- Spawns sub-agents via task() tool
- Makes intelligent decisions using LLM reasoning
- Stores all results in Nexus/GCS workspace
- Aggregates findings into final report

Reference:
- Issue #16: Create Recon Coordinator (LangGraph)
- DeepAgents: https://github.com/langchain-ai/deepagents
- Syntar implementation: /Users/tafeng/syntar/backend
"""

import logging
from typing import Any, Optional

from deepagents import create_deep_agent, SubAgent
from langchain_openai import ChatOpenAI

from agents.backends.nexus_backend import NexusBackend
from agents.tools.recon_tools import run_subfinder, run_httpx, run_nmap

logger = logging.getLogger(__name__)


def create_subfinder_subagent(
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    model: Optional[Any] = None
) -> Any:
    """
    Create Subfinder sub-agent (DeepAgent).

    This is a specialized sub-agent that uses the run_subfinder tool
    to discover subdomains for a target domain.

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        model: LLM model (default: GPT-4o-mini via OpenRouter)

    Returns:
        DeepAgent configured for subdomain discovery
    """
    if model is None:
        import os
        model = ChatOpenAI(
            model="openai/gpt-4o-mini",
            openai_api_key=os.getenv("OPENROUTER_API_KEY"),
            openai_api_base="https://openrouter.ai/api/v1",
            temperature=0
        )

    system_prompt = """You are a Subdomain Discovery Specialist.

Your mission: Discover subdomains for a target domain using Subfinder.

**Available Tools:**
- run_subfinder: Discovers subdomains via passive reconnaissance

**Workflow:**
1. Use run_subfinder with the target domain
2. Read results from /recon/subfinder/subdomains.json
3. Report findings concisely

**Output Format:**
- Number of subdomains found
- Notable subdomains (admin, api, vpn, staging, dev, etc.)
- Success/failure status

Be concise and factual. Focus on actionable intelligence."""

    return create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=system_prompt,
        tools=[run_subfinder]
    )


def create_httpx_subagent(
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    model: Optional[Any] = None
) -> Any:
    """
    Create HTTPx sub-agent (DeepAgent).

    This is a specialized sub-agent that uses the run_httpx tool
    to probe subdomains and identify live HTTP/HTTPS services.

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        model: LLM model (default: GPT-4o-mini via OpenRouter)

    Returns:
        DeepAgent configured for HTTP probing
    """
    if model is None:
        import os
        model = ChatOpenAI(
            model="openai/gpt-4o-mini",
            openai_api_key=os.getenv("OPENROUTER_API_KEY"),
            openai_api_base="https://openrouter.ai/api/v1",
            temperature=0
        )

    system_prompt = """You are an HTTP/HTTPS Probing Specialist.

Your mission: Probe discovered subdomains to identify live hosts.

**Available Tools:**
- run_httpx: Probes targets for HTTP/HTTPS services

**Workflow:**
1. Use run_httpx with the list of targets
2. Read results from /recon/httpx/live_hosts.json
3. Report findings concisely

**Output Format:**
- Number of live hosts found
- Technologies detected (web servers, frameworks)
- Notable hosts (databases, admin panels, APIs)
- Success/failure status

Be concise and factual. Focus on actionable intelligence."""

    return create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=system_prompt,
        tools=[run_httpx]
    )


def create_nmap_subagent(
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    model: Optional[Any] = None
) -> Any:
    """
    Create Nmap sub-agent (DeepAgent).

    This is a specialized sub-agent that uses the run_nmap tool
    to scan hosts for open ports and running services.

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        model: LLM model (default: GPT-4o-mini via OpenRouter)

    Returns:
        DeepAgent configured for port scanning
    """
    if model is None:
        import os
        model = ChatOpenAI(
            model="openai/gpt-4o-mini",
            openai_api_key=os.getenv("OPENROUTER_API_KEY"),
            openai_api_base="https://openrouter.ai/api/v1",
            temperature=0
        )

    system_prompt = """You are a Network Scanning Specialist.

Your mission: Scan live hosts to discover open ports and services.

**Available Tools:**
- run_nmap: Scans targets for open ports and services

**Workflow:**
1. Use run_nmap with the list of targets
2. Read results from /recon/nmap/scan_results.json
3. Report findings concisely

**Scan Profiles:**
- "stealth": Slow, evasive scan
- "default": Balanced scan with service detection
- "aggressive": Fast, comprehensive scan

**Output Format:**
- Number of hosts scanned
- Total open ports found
- Critical services (SSH, databases, admin panels)
- Vulnerable versions detected
- Success/failure status

Be concise and factual. Focus on security-relevant findings."""

    return create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=system_prompt,
        tools=[run_nmap]
    )


def _create_bound_tools(scan_id: str, team_id: str, backend: NexusBackend):
    """
    Create recon tools with bound context.

    This creates closures around the tools that inject the backend context
    without relying on thread-local storage (which doesn't work with LangGraph's threading).
    """
    from functools import wraps
    from langchain_core.tools import StructuredTool

    # Create wrapper functions that bind the context
    def make_run_subfinder():
        @wraps(run_subfinder.func)
        def bound_subfinder(*args, **kwargs):
            # Temporarily set context for this tool execution
            from agents.context import set_agent_context
            set_agent_context(scan_id, team_id, backend)
            return run_subfinder.func(*args, **kwargs)

        # Create new tool with bound function
        return StructuredTool.from_function(
            func=bound_subfinder,
            name=run_subfinder.name,
            description=run_subfinder.description,
            args_schema=run_subfinder.args_schema
        )

    def make_run_httpx():
        @wraps(run_httpx.func)
        def bound_httpx(*args, **kwargs):
            from agents.context import set_agent_context
            set_agent_context(scan_id, team_id, backend)
            return run_httpx.func(*args, **kwargs)

        return StructuredTool.from_function(
            func=bound_httpx,
            name=run_httpx.name,
            description=run_httpx.description,
            args_schema=run_httpx.args_schema
        )

    def make_run_nmap():
        @wraps(run_nmap.func)
        def bound_nmap(*args, **kwargs):
            from agents.context import set_agent_context
            set_agent_context(scan_id, team_id, backend)
            return run_nmap.func(*args, **kwargs)

        return StructuredTool.from_function(
            func=bound_nmap,
            name=run_nmap.name,
            description=run_nmap.description,
            args_schema=run_nmap.args_schema
        )

    return {
        'subfinder': make_run_subfinder(),
        'httpx': make_run_httpx(),
        'nmap': make_run_nmap()
    }


def create_recon_coordinator(
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    model: Optional[Any] = None
) -> Any:
    """
    Create Recon Coordinator (orchestrator DeepAgent).

    This is the main coordinator agent that orchestrates the complete
    reconnaissance workflow by spawning and coordinating sub-agents.

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        model: LLM model (default: Claude Sonnet 4 via OpenRouter)

    Returns:
        DeepAgent configured as reconnaissance coordinator

    Example:
        >>> from config.nexus_config import get_nexus_fs
        >>> from agents.backends.nexus_backend import NexusBackend
        >>>
        >>> backend = NexusBackend("scan-123", "team-abc", get_nexus_fs())
        >>> coordinator = create_recon_coordinator("scan-123", "team-abc", backend)
        >>> result = coordinator.invoke({
        ...     "messages": [{"role": "user", "content": "Scan example.com"}]
        ... })
    """
    if model is None:
        import os
        model = ChatOpenAI(
            model="anthropic/claude-3.5-sonnet",
            api_key=os.getenv("OPENROUTER_API_KEY"),  # Use api_key (not openai_api_key)
            base_url="https://openrouter.ai/api/v1",  # Use base_url (not openai_api_base)
            temperature=0
        )

    # Create tools with bound context
    bound_tools = _create_bound_tools(scan_id, team_id, backend)

    system_prompt = """You are a Cybersecurity Reconnaissance Coordinator.

Your mission: Orchestrate a complete reconnaissance workflow for target domains.

**Available Sub-Agents:**
You can spawn specialized sub-agents using the task() tool:
- "subfinder" - Discovers subdomains via passive reconnaissance
- "httpx" - Probes subdomains for live HTTP/HTTPS services
- "nmap" - Scans live hosts for open ports and services

**Workflow Strategy:**
1. DISCOVERY: Spawn subfinder sub-agent to discover subdomains
   - task(agent_type="subfinder", description="Discover subdomains for {domain}")
   - Read results from /recon/subfinder/subdomains.json

2. ANALYSIS & PRIORITIZATION:
   - If >100 subdomains found: Prioritize high-value targets
   - Look for: admin, api, vpn, staging, dev, db, mysql, postgres, redis
   - Select top 20-30 most interesting targets

3. HTTP PROBING: Spawn httpx sub-agent to identify live hosts
   - task(agent_type="httpx", description="Probe these targets: {list}")
   - Read results from /recon/httpx/live_hosts.json

4. SERVICE ANALYSIS:
   - Identify critical services (databases, admin panels, APIs)
   - Look for technology stacks (versions, frameworks)
   - Prioritize hosts with interesting services

5. PORT SCANNING: Spawn nmap sub-agent to scan live hosts
   - task(agent_type="nmap", description="Scan these hosts: {list}")
   - Read results from /recon/nmap/scan_results.json

6. FINAL REPORT: Aggregate all findings
   - Write comprehensive report to /recon/final_report.json
   - Include: summary, high-risk findings, recommendations

**Decision Making:**
- If >100 subdomains: Limit to top 20-30 high-value targets
- If database ports exposed: Flag as HIGH RISK
- If old SSH/HTTP versions: Flag as MEDIUM RISK
- If admin/staging exposed: Flag as MEDIUM RISK

**Output Format:**
Write final report as JSON:
{
  "scan_id": "{scan_id}",
  "target": "{domain}",
  "timestamp": "{iso timestamp}",
  "summary": {
    "total_subdomains": N,
    "live_hosts": N,
    "total_open_ports": N
  },
  "high_risk_findings": [
    "Database port 3306 exposed on db.example.com",
    "Old SSH version on admin.example.com"
  ],
  "medium_risk_findings": [...],
  "recommendations": [...]
}

Be thorough, intelligent, and security-focused. Make smart decisions about what to scan."""

    # Register sub-agents that coordinator can spawn
    # Use bound tools so each sub-agent has access to the backend
    sub_agents = [
        SubAgent(
            name="subfinder",
            description="Subdomain discovery specialist using Subfinder tool",
            system_prompt="""You are a Subdomain Discovery Specialist.
Use run_subfinder tool to discover subdomains. Read results from /recon/subfinder/subdomains.json and report findings.""",
            tools=[bound_tools['subfinder']]
        ),
        SubAgent(
            name="httpx",
            description="HTTP/HTTPS probing specialist using HTTPx tool",
            system_prompt="""You are an HTTP/HTTPS Probing Specialist.
Use run_httpx tool to probe targets. Read results from /recon/httpx/live_hosts.json and report findings.""",
            tools=[bound_tools['httpx']]
        ),
        SubAgent(
            name="nmap",
            description="Network scanning specialist using Nmap tool",
            system_prompt="""You are a Network Scanning Specialist.
Use run_nmap tool to scan ports. Read results from /recon/nmap/scan_results.json and report findings.""",
            tools=[bound_tools['nmap']]
        )
    ]

    # Coordinator uses built-in subagents support in create_deep_agent
    # and built-in file tools to read/write results
    return create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=system_prompt,
        subagents=sub_agents
    )


# ============================================================================
# LangGraph Server Export (for LangGraph Studio / langgraph dev)
# ============================================================================
#
# The graph must be exported as a module-level variable for fast schema loading.
# LangGraph will call the graph directly with config at runtime.
#
# For local testing, use demo_recon_coordinator.py instead.
# ============================================================================
