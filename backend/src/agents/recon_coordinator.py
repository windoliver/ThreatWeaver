"""
Recon Coordinator - LangGraph-based orchestration of reconnaissance agents.

This module implements Issue #16: Create Recon Coordinator (LangGraph).

The ReconCoordinator is a DeepAgent that orchestrates the complete reconnaissance
workflow by spawning and coordinating sub-agents (Subfinder, HTTPx, Nmap, ffuf).

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
from typing import Any, Optional, Dict

from deepagents import create_deep_agent, SubAgent
from langchain_openai import ChatOpenAI

from agents.backends.nexus_backend import NexusBackend
from agents.tools.recon_tools import run_subfinder, run_httpx, run_nmap, run_ffuf, run_wafw00f

logger = logging.getLogger(__name__)


def _get_tools():
    """
    Get recon tools for sub-agents.

    The tools automatically extract thread_id from LangGraph's RunnableConfig
    and create their own backend. No binding needed.
    """
    return {
        'subfinder': run_subfinder,
        'httpx': run_httpx,
        'nmap': run_nmap,
        'ffuf': run_ffuf,
        'wafw00f': run_wafw00f,
    }


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
            model="anthropic/claude-sonnet-4",
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            temperature=0
        )

    # Get recon tools (they auto-extract config from LangGraph runtime)
    tools = _get_tools()

    system_prompt = """You are a Cybersecurity Reconnaissance Coordinator.

Your mission: Orchestrate a complete reconnaissance workflow for target domains.

**Available Sub-Agents:**
You can spawn specialized sub-agents using the task() tool:
- "subfinder" - Discovers subdomains via passive reconnaissance
- "httpx" - Probes subdomains for live HTTP/HTTPS services
- "nmap" - Scans live hosts for open ports and services
- "ffuf" - Discovers hidden directories and files via brute-forcing
- "wafw00f" - Detects Web Application Firewalls (WAFs)

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

4. WAF DETECTION: Spawn wafw00f sub-agent on live hosts
   - task(agent_type="wafw00f", description="Detect WAFs on these targets: {list}")
   - Read results from /recon/wafw00f/findings.json
   - Knowing the WAF is critical for adjusting exploitation techniques

5. DIRECTORY DISCOVERY: Spawn ffuf sub-agent on key targets
   - task(agent_type="ffuf", description="Discover hidden paths on {url}")
   - Read results from /recon/ffuf/findings.json
   - Focus on admin panels, APIs, and high-value hosts

6. PORT SCANNING: Spawn nmap sub-agent to scan live hosts
   - task(agent_type="nmap", description="Scan these hosts: {list}")
   - Read results from /recon/nmap/scan_results.json

7. FINAL REPORT: Aggregate all findings
   - Write comprehensive report to /recon/final_report.json
   - Include: summary, high-risk findings, recommendations

**Decision Making:**
- If >100 subdomains: Limit to top 20-30 high-value targets
- If database ports exposed: Flag as HIGH RISK
- If old SSH/HTTP versions: Flag as MEDIUM RISK
- If admin/staging exposed: Flag as MEDIUM RISK
- If hidden admin paths found: Flag as HIGH RISK
- If WAF detected: Note in report and adjust exploitation strategy accordingly

**Output Format:**
Write final report as JSON:
{
  "scan_id": "{scan_id}",
  "target": "{domain}",
  "timestamp": "{iso timestamp}",
  "summary": {
    "total_subdomains": N,
    "live_hosts": N,
    "total_open_ports": N,
    "hidden_paths_found": N
  },
  "high_risk_findings": [
    "Database port 3306 exposed on db.example.com",
    "Hidden admin panel at /admin-backup",
    "Old SSH version on admin.example.com"
  ],
  "medium_risk_findings": [...],
  "recommendations": [...]
}

Be thorough, intelligent, and security-focused. Make smart decisions about what to scan."""

    # Register sub-agents that coordinator can spawn
    sub_agents = [
        SubAgent(
            name="subfinder",
            description="Subdomain discovery specialist using Subfinder tool",
            system_prompt="""You are a Subdomain Discovery Specialist.
Use run_subfinder tool to discover subdomains. Read results from /recon/subfinder/subdomains.json and report findings.""",
            tools=[tools['subfinder']]
        ),
        SubAgent(
            name="httpx",
            description="HTTP/HTTPS probing specialist using HTTPx tool",
            system_prompt="""You are an HTTP/HTTPS Probing Specialist.
Use run_httpx tool to probe targets. Read results from /recon/httpx/live_hosts.json and report findings.""",
            tools=[tools['httpx']]
        ),
        SubAgent(
            name="nmap",
            description="Network scanning specialist using Nmap tool",
            system_prompt="""You are a Network Scanning Specialist.
Use run_nmap tool to scan ports. Read results from /recon/nmap/scan_results.json and report findings.""",
            tools=[tools['nmap']]
        ),
        SubAgent(
            name="ffuf",
            description="Directory and file brute-forcing specialist using ffuf tool",
            system_prompt="""You are a Directory Discovery Specialist.
Use run_ffuf tool to discover hidden directories and files. Read results from /recon/ffuf/findings.json and report findings.

**Best Practices:**
- Start with "common" wordlist for quick results
- Use extensions like .php, .bak, .old, .zip for sensitive files
- Filter out false positives using filter_size if default pages have consistent size
- Focus on interesting status codes: 200, 301, 302, 401, 403

Report any interesting findings like admin panels, backup files, or sensitive endpoints.""",
            tools=[tools['ffuf']]
        ),
        SubAgent(
            name="wafw00f",
            description="WAF detection specialist using wafw00f tool",
            system_prompt="""You are a WAF Detection Specialist.
Use run_wafw00f tool to detect Web Application Firewalls. Read results from /recon/wafw00f/findings.json and report findings.

**Key Information to Report:**
- Which targets have WAFs detected
- WAF vendor/product names (e.g., Cloudflare, AWS WAF, Akamai)
- Confidence level of detection (high, medium, low)

Knowing the WAF is critical for adjusting exploitation techniques. Report all detected WAFs clearly.""",
            tools=[tools['wafw00f']]
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
