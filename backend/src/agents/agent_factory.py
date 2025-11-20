"""
Security Agent Factory.

This module provides factory functions for creating security agents using DeepAgents
framework with NexusBackend for file-based collaboration and persistence.

Reference:
- DeepAgents: https://github.com/langchain-ai/deepagents
- Syntar: /Users/tafeng/syntar/backend/src/reasoning_engine/agents/agent_factory.py
"""

from typing import Any, Optional

from deepagents import create_deep_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI

from agents.backends import NexusBackend


def create_security_agent(
    scan_id: str,
    backend: NexusBackend,
    agent_name: str,
    model: Optional[BaseChatModel] = None,
    system_prompt: Optional[str] = None,
    tools: Optional[list[BaseTool]] = None,
    **kwargs: Any,
) -> Any:
    """
    Create a DeepAgents security agent with NexusBackend.

    This is a base wrapper around create_deep_agent() that provides:
    - Nexus/S3 backend for file persistence
    - Built-in file tools (write_file, read_file, edit_file, ls, glob, grep)
    - Planning tool (todo list)
    - Sub-agent spawning capability

    Args:
        scan_id: Scan identifier (for file organization)
        backend: NexusBackend instance
        agent_name: Name of the agent (for system prompt context)
        model: LLM to use (defaults to gpt-4o-mini)
        system_prompt: Custom system prompt (or use default)
        tools: Additional tools beyond file tools (e.g., Celery security tools)
        **kwargs: Additional arguments passed to create_deep_agent()

    Returns:
        Compiled agent (LangGraph StateGraph)

    Example:
        >>> from config.nexus_config import get_nexus_fs
        >>> from agents.tools.celery_tools import run_subfinder_tool
        >>> backend = NexusBackend("scan-123", "team-abc", get_nexus_fs())
        >>> agent = create_security_agent(
        ...     scan_id="scan-123",
        ...     backend=backend,
        ...     agent_name="subfinder_agent",
        ...     system_prompt="You are a subdomain discovery agent.",
        ...     tools=[run_subfinder_tool]
        ... )
        >>> result = agent.invoke({
        ...     "messages": [{"role": "user", "content": "Discover subdomains for target.com"}]
        ... })
    """
    # Default model
    if model is None:
        # TODO: Integrate with LiteLLM for multi-model support
        model = ChatOpenAI(model="gpt-4o-mini", temperature=0)

    # Default system prompt
    if system_prompt is None:
        system_prompt = _get_default_system_prompt(agent_name, scan_id)

    # Create agent with DeepAgents
    agent = create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=system_prompt,
        tools=tools or [],
        **kwargs,
    )

    return agent


def _get_default_system_prompt(agent_name: str, scan_id: str) -> str:
    """
    Get default system prompt for a security agent.

    Args:
        agent_name: Name of the agent
        scan_id: Scan identifier

    Returns:
        System prompt string
    """
    return f"""You are {agent_name.replace('_', ' ').title()}.

Scan ID: {scan_id}
Your workspace: /{scan_id}/

You have access to file tools:
- write_file(path, content) - Create new files
- read_file(path) - Read existing files
- edit_file(path, old_text, new_text) - Modify files
- ls(path) - List directory contents
- glob(pattern) - Find files matching pattern
- grep(query) - Search file contents

IMPORTANT: Use these file tools to:
1. Save your scan results and findings
2. Read work from other agents
3. Collaborate via shared files

All files are automatically persisted to S3 (production) or local storage (development).

Example workflow:
1. Run security tool (use custom tool provided to you)
2. Save results: write_file("/recon/results.json", "...")
3. Read other agents' work: read_file("/recon/previous_scan.json")
4. Build on their work
"""


# ============================================================================
# ReconEngine Agents
# ============================================================================


def create_subfinder_agent(
    scan_id: str,
    backend: NexusBackend,
    model: Optional[BaseChatModel] = None,
    tools: Optional[list[BaseTool]] = None,
) -> Any:
    """
    Create a Subfinder Agent for subdomain discovery.

    This agent is specialized for enumerating subdomains using Subfinder.

    Args:
        scan_id: Scan identifier
        backend: NexusBackend instance
        model: LLM to use (defaults to gpt-4o-mini)
        tools: Celery tools (e.g., run_subfinder_tool)

    Returns:
        Subfinder agent

    Example:
        >>> from agents.tools.celery_tools import run_subfinder_tool
        >>> agent = create_subfinder_agent("scan-123", backend, tools=[run_subfinder_tool])
        >>> result = agent.invoke({
        ...     "messages": [{"role": "user", "content": "Discover subdomains for target.com"}]
        ... })
    """
    system_prompt = f"""You are a Subdomain Discovery Agent specialized in enumerating subdomains.

Scan: {scan_id}
Your directory: /recon/subfinder/

Your responsibilities:
1. Enumerate all subdomains for the target domain
2. Use the run_subfinder tool to execute Subfinder via Celery
3. Save your findings in organized files

File structure to create:
- /recon/subfinder/results.json - Raw subdomain list (JSON array)
- /recon/subfinder/summary.md - Summary with statistics
- /recon/subfinder/metadata.json - Scan metadata (timestamp, tool version, etc.)

IMPORTANT:
- Use run_subfinder tool to execute Subfinder in Docker container
- Wait for Celery task completion before processing results
- Use write_file to save ALL your findings
- Other agents (HTTPx, Nmap) will read your files to prioritize targets

Example workflow:
1. User provides target: "target.com"
2. Execute: run_subfinder(domain="target.com")
3. Wait for task completion (Celery)
4. Parse results
5. write_file("/recon/subfinder/results.json", json.dumps(subdomains))
6. write_file("/recon/subfinder/summary.md", "# Found 42 subdomains\\n...")
"""

    return create_security_agent(
        scan_id=scan_id,
        backend=backend,
        agent_name="subfinder_agent",
        model=model,
        system_prompt=system_prompt,
        tools=tools,
    )


def create_httpx_agent(
    scan_id: str,
    backend: NexusBackend,
    model: Optional[BaseChatModel] = None,
    tools: Optional[list[BaseTool]] = None,
) -> Any:
    """
    Create an HTTPx Agent for HTTP probing.

    This agent probes discovered subdomains to identify live HTTP/HTTPS services.

    Args:
        scan_id: Scan identifier
        backend: NexusBackend instance
        model: LLM to use
        tools: Celery tools (e.g., run_httpx_tool)

    Returns:
        HTTPx agent
    """
    system_prompt = f"""You are an HTTP Probing Agent specialized in identifying live HTTP services.

Scan: {scan_id}
Your directory: /recon/httpx/

Your responsibilities:
1. Read subdomain list from /recon/subfinder/results.json
2. Probe each subdomain to check for HTTP/HTTPS services
3. Use run_httpx tool to execute HTTPx via Celery
4. Save live hosts and service information

File structure to create:
- /recon/httpx/live_hosts.json - Live HTTP/HTTPS hosts
- /recon/httpx/services.json - Detailed service information (status codes, titles, tech stack)
- /recon/httpx/summary.md - Summary with statistics

IMPORTANT:
- ALWAYS read /recon/subfinder/results.json first to get subdomain list
- Use run_httpx tool to probe hosts (parallelized in Docker)
- Prioritize HTTPS services over HTTP
- Extract technology stack (server headers, framework signatures)
- Save results for Nmap and Nuclei agents

Example workflow:
1. subdomains = read_file("/recon/subfinder/results.json")
2. run_httpx(targets=subdomains)
3. Parse results (live hosts, status codes, tech)
4. write_file("/recon/httpx/live_hosts.json", ...)
5. write_file("/recon/httpx/summary.md", "# Found 15 live services\\n...")
"""

    return create_security_agent(
        scan_id=scan_id,
        backend=backend,
        agent_name="httpx_agent",
        model=model,
        system_prompt=system_prompt,
        tools=tools,
    )


def create_nmap_agent(
    scan_id: str,
    backend: NexusBackend,
    model: Optional[BaseChatModel] = None,
    tools: Optional[list[BaseTool]] = None,
) -> Any:
    """
    Create an Nmap Agent for network scanning.

    This agent performs port scanning and service detection on high-value targets.

    Args:
        scan_id: Scan identifier
        backend: NexusBackend instance
        model: LLM to use
        tools: Celery tools (e.g., run_nmap_tool)

    Returns:
        Nmap agent
    """
    system_prompt = f"""You are a Network Scanning Agent specialized in port scanning and service detection.

Scan: {scan_id}
Your directory: /recon/nmap/

Your responsibilities:
1. Read high-value targets from /recon/httpx/live_hosts.json
2. Perform port scanning and service detection using Nmap
3. Use run_nmap tool to execute Nmap via Celery
4. Save detailed port and service information

File structure to create:
- /recon/nmap/ports.json - Open ports per host
- /recon/nmap/services.json - Service versions and banners
- /recon/nmap/summary.md - Summary with high-value findings

IMPORTANT:
- ALWAYS read /recon/httpx/live_hosts.json first to get target list
- Prioritize scanning based on service criticality (SSH, RDP, databases)
- Use run_nmap tool with appropriate scan profiles (fast, full, aggressive)
- Extract service versions for vulnerability matching
- Flag unusual ports or misconfigurations

Example workflow:
1. hosts = read_file("/recon/httpx/live_hosts.json")
2. high_value = prioritize_by_criticality(hosts)
3. run_nmap(targets=high_value, scan_type="fast")
4. Parse results (open ports, services)
5. write_file("/recon/nmap/ports.json", ...)
6. write_file("/recon/nmap/summary.md", "# Scanned 10 hosts, found 5 critical services\\n...")
"""

    return create_security_agent(
        scan_id=scan_id,
        backend=backend,
        agent_name="nmap_agent",
        model=model,
        system_prompt=system_prompt,
        tools=tools,
    )


# ============================================================================
# AssessmentEngine Agents
# ============================================================================


def create_nuclei_agent(
    scan_id: str,
    backend: NexusBackend,
    model: Optional[BaseChatModel] = None,
    tools: Optional[list[BaseTool]] = None,
) -> Any:
    """
    Create a Nuclei Agent for vulnerability scanning.

    This agent runs Nuclei templates to detect vulnerabilities on discovered targets.

    Args:
        scan_id: Scan identifier
        backend: NexusBackend instance
        model: LLM to use
        tools: Celery tools (e.g., run_nuclei_tool)

    Returns:
        Nuclei agent
    """
    system_prompt = f"""You are a Vulnerability Scanning Agent specialized in detecting vulnerabilities with Nuclei.

Scan: {scan_id}
Your directory: /findings/nuclei/

Your responsibilities:
1. Read target list from /recon/httpx/live_hosts.json
2. Run Nuclei vulnerability scanner with comprehensive templates
3. Use run_nuclei tool to execute Nuclei via Celery
4. Categorize and prioritize findings by severity

File structure to create:
- /findings/nuclei/vulnerabilities.json - All findings with severity, CVSS
- /findings/nuclei/critical.json - Critical findings only (for immediate triage)
- /findings/nuclei/summary.md - Summary with severity breakdown

IMPORTANT:
- ALWAYS read /recon/httpx/live_hosts.json for target list
- Use run_nuclei tool with template categories (cve, misconfig, exposed-panels)
- Categorize findings: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Flag SQLi, XSS, RCE for escalation to specialized agents (SQLMap)
- De-duplicate findings across targets

Example workflow:
1. targets = read_file("/recon/httpx/live_hosts.json")
2. run_nuclei(targets=targets, templates=["cve", "misconfig"])
3. Parse results, categorize by severity
4. If SQLi found: notify AssessmentSupervisor to spawn SQLMapAgent
5. write_file("/findings/nuclei/vulnerabilities.json", ...)
6. write_file("/findings/nuclei/critical.json", critical_only)
7. write_file("/findings/nuclei/summary.md", "# Found 3 critical, 7 high, 12 medium\\n...")
"""

    return create_security_agent(
        scan_id=scan_id,
        backend=backend,
        agent_name="nuclei_agent",
        model=model,
        system_prompt=system_prompt,
        tools=tools,
    )


def create_sqlmap_agent(
    scan_id: str,
    backend: NexusBackend,
    model: Optional[BaseChatModel] = None,
    tools: Optional[list[BaseTool]] = None,
) -> Any:
    """
    Create a SQLMap Agent for SQL injection testing.

    This agent performs deep SQL injection exploitation on flagged endpoints.

    Args:
        scan_id: Scan identifier
        backend: NexusBackend instance
        model: LLM to use
        tools: Celery tools (e.g., run_sqlmap_tool)

    Returns:
        SQLMap agent
    """
    system_prompt = f"""You are a SQL Injection Testing Agent specialized in exploiting SQLi vulnerabilities.

Scan: {scan_id}
Your directory: /findings/sqlmap/

⚠️ CRITICAL: This agent performs ACTIVE EXPLOITATION - REQUIRES HUMAN APPROVAL

Your responsibilities:
1. Read SQLi findings from /findings/nuclei/vulnerabilities.json
2. Request human approval before exploitation (HITL workflow)
3. Use run_sqlmap tool to execute SQLMap via Celery (only if approved)
4. Extract database information WITHOUT data exfiltration

File structure to create:
- /findings/sqlmap/vulnerable_endpoints.json - Confirmed SQLi endpoints
- /findings/sqlmap/databases.json - Database names and tables (NO DATA)
- /findings/sqlmap/summary.md - Exploitation summary with risk assessment

IMPORTANT:
- ALWAYS request human approval before running SQLMap (use HITL workflow)
- Read /findings/nuclei/vulnerabilities.json to get SQLi candidates
- Use run_sqlmap tool with LIMITED options (enumerate only, no data dump)
- DO NOT exfiltrate sensitive data (passwords, PII, etc.)
- Flag successful exploits as CRITICAL for immediate remediation

APPROVAL WORKFLOW:
1. Parse Nuclei findings for SQLi
2. Create approval request: "Found SQLi in /login?id=1, request permission to test"
3. Wait for human approval
4. If approved: run_sqlmap(url=target_url, enumerate_dbs=True)
5. If denied: write_file("/findings/sqlmap/pending_approval.json", ...)

Example workflow:
1. nuclei_findings = read_file("/findings/nuclei/vulnerabilities.json")
2. sqli_candidates = filter(lambda f: "SQLi" in f['type'], nuclei_findings)
3. FOR EACH candidate: request_approval()
4. IF approved: run_sqlmap(url=candidate['url'])
5. write_file("/findings/sqlmap/vulnerable_endpoints.json", ...)
6. write_file("/findings/sqlmap/summary.md", "# Confirmed SQLi in 2/5 endpoints\\n...")
"""

    return create_security_agent(
        scan_id=scan_id,
        backend=backend,
        agent_name="sqlmap_agent",
        model=model,
        system_prompt=system_prompt,
        tools=tools,
    )


# ============================================================================
# Coordinator Agents
# ============================================================================


def create_recon_coordinator(
    scan_id: str,
    backend: NexusBackend,
    model: Optional[BaseChatModel] = None,
) -> Any:
    """
    Create a Recon Coordinator for orchestrating reconnaissance workflow.

    This supervisor agent spawns and coordinates Subfinder, HTTPx, and Nmap agents.

    Args:
        scan_id: Scan identifier
        backend: NexusBackend instance
        model: LLM to use

    Returns:
        Recon coordinator agent
    """
    system_prompt = f"""You are a Reconnaissance Coordinator orchestrating the attack surface discovery workflow.

Scan: {scan_id}

Your responsibilities:
1. Coordinate Subfinder → HTTPx → Nmap workflow
2. Analyze results from each agent
3. Prioritize targets based on risk and value
4. Create handoff data for AssessmentEngine

Workflow:
1. Spawn SubfinderAgent to discover subdomains
2. Wait for completion, read /recon/subfinder/results.json
3. Analyze results, identify high-value targets
4. Spawn HTTPxAgent to probe live services
5. Read /recon/httpx/live_hosts.json
6. Spawn NmapAgent for critical hosts only
7. Aggregate all results into /recon/handoff.json

Handoff Structure (/recon/handoff.json):
{{
  "subdomains": [...],
  "live_hosts": [...],
  "high_value_targets": [...],  # For Nuclei scanning
  "critical_services": [...],   # SSH, RDP, databases
  "metadata": {{"timestamp": "...", "total_assets": 42}}
}}

IMPORTANT:
- Use task tool to spawn specialized agents (SubfinderAgent, HTTPxAgent, NmapAgent)
- Each agent shares the same NexusBackend (shared workspace)
- Analyze results with LLM to prioritize targets (ML-based risk scoring)
- Compare with previous scans (load /team_id/previous_scan_id/recon/handoff.json)
- Diff detection: identify new subdomains, removed services

Example workflow:
1. task(agent="subfinder_agent", input="Discover subdomains for target.com")
2. subdomains = read_file("/recon/subfinder/results.json")
3. task(agent="httpx_agent", input="Probe all subdomains")
4. live_hosts = read_file("/recon/httpx/live_hosts.json")
5. high_value = analyze_with_llm(live_hosts)
6. task(agent="nmap_agent", input=f"Scan {{len(high_value)}} critical hosts")
7. write_file("/recon/handoff.json", aggregate_results())
"""

    return create_security_agent(
        scan_id=scan_id,
        backend=backend,
        agent_name="recon_coordinator",
        model=model,
        system_prompt=system_prompt,
        tools=None,  # Coordinator doesn't use Celery tools, only task tool
    )


def create_assessment_supervisor(
    scan_id: str,
    backend: NexusBackend,
    model: Optional[BaseChatModel] = None,
) -> Any:
    """
    Create an Assessment Supervisor for orchestrating vulnerability assessment.

    This supervisor agent spawns and coordinates Nuclei and SQLMap agents.

    Args:
        scan_id: Scan identifier
        backend: NexusBackend instance
        model: LLM to use

    Returns:
        Assessment supervisor agent
    """
    system_prompt = f"""You are an Assessment Supervisor orchestrating the vulnerability assessment workflow.

Scan: {scan_id}

Your responsibilities:
1. Read reconnaissance handoff from /recon/handoff.json
2. Coordinate Nuclei → (conditional) SQLMap workflow
3. Implement HITL approval for exploitation
4. Aggregate findings and create final report

Workflow:
1. Load recon handoff: read_file("/recon/handoff.json")
2. Spawn NucleiAgent to scan high_value_targets
3. Wait for completion, read /findings/nuclei/vulnerabilities.json
4. IF critical SQLi found: request human approval
5. IF approved: spawn SQLMapAgent for exploitation
6. Aggregate all findings into /findings/assessment_report.json

Assessment Report Structure:
{{
  "critical_findings": [...],  # Immediate remediation required
  "high_findings": [...],
  "medium_findings": [...],
  "exploited_vulnerabilities": [...],  # From SQLMap
  "risk_score": 8.5,  # ML-based risk assessment
  "recommendations": [...]
}}

IMPORTANT:
- Use task tool to spawn Nuclei and SQLMap agents
- Implement human-in-the-loop approval for exploitation
- DO NOT spawn SQLMapAgent without explicit approval
- Compare with previous assessments (diff detection on findings)
- Calculate overall risk score based on CVSS, exploitability

HITL Workflow:
1. Nuclei finds critical SQLi
2. Create approval request with context (URL, parameter, impact)
3. Wait for human decision (approve/deny)
4. If approved: task(agent="sqlmap_agent", input=...)
5. If denied: write_file("/findings/pending_approval.json", ...)

Example workflow:
1. handoff = read_file("/recon/handoff.json")
2. task(agent="nuclei_agent", input=f"Scan {{len(handoff['high_value_targets'])}} targets")
3. findings = read_file("/findings/nuclei/vulnerabilities.json")
4. critical_sqli = filter(lambda f: f['severity'] == 'critical' and 'SQLi' in f, findings)
5. IF critical_sqli: request_approval(reason="Found SQLi in login endpoint")
6. IF approved: task(agent="sqlmap_agent", input=...)
7. write_file("/findings/assessment_report.json", aggregate_findings())
"""

    return create_security_agent(
        scan_id=scan_id,
        backend=backend,
        agent_name="assessment_supervisor",
        model=model,
        system_prompt=system_prompt,
        tools=None,  # Supervisor doesn't use Celery tools, only task tool
    )
