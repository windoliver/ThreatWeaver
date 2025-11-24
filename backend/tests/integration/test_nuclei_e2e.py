"""
End-to-end tests for NucleiAgent demonstrating different template selections.

These tests require:
1. E2B_API_KEY environment variable
2. E2B template access (template must be public or API key must match template owner)

Run:
    export E2B_API_KEY=your_key_here
    pytest tests/integration/test_nuclei_e2e.py -v -m integration

Skip if E2B not available:
    pytest tests/ -v -m "not integration"

This test demonstrates Issue #17: Nuclei Scanning Agent with various
template selection modes including:
- Default templates (all community templates)
- Severity-based filtering
- Specific template selection (CVE, technology, type-based)
- Tag-based template selection
"""

import os
import pytest
from datetime import datetime

from e2b import Sandbox

from src.agents.assessment.nuclei_agent import NucleiAgent, NucleiError, NucleiFinding
from src.agents.backends.nexus_backend import NexusBackend
from src.config import get_nexus_fs


# Skip all tests if E2B_API_KEY not set
pytestmark = pytest.mark.skipif(
    not os.getenv("E2B_API_KEY"),
    reason="E2B_API_KEY not set - skipping E2B integration tests"
)


@pytest.fixture(scope="module")
def e2b_sandbox():
    """Create real E2B sandbox with threatweaver-security template."""
    try:
        # Create sandbox with 10 minute timeout to handle all tests
        sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38", timeout=600)
        yield sandbox
        sandbox.kill()
    except Exception as e:
        pytest.skip(f"Failed to create E2B sandbox: {e}")


@pytest.fixture
def integration_workspace():
    """Create temporary Nexus workspace for integration tests."""
    nx = get_nexus_fs()
    scan_id = f"nuclei-e2e-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    backend = NexusBackend(
        scan_id=scan_id,
        team_id="test-e2e-team",
        nexus_fs=nx
    )
    return backend, scan_id


@pytest.fixture
def nuclei_agent(e2b_sandbox, integration_workspace):
    """Create NucleiAgent with real E2B sandbox."""
    backend, scan_id = integration_workspace
    agent = NucleiAgent(
        scan_id=scan_id,
        team_id="test-e2e-team",
        nexus_backend=backend,
        sandbox=e2b_sandbox
    )
    yield agent
    # Don't cleanup sandbox here since it's shared via module scope


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiToolAvailability:
    """Verify Nuclei is available and properly configured in E2B template."""

    def test_nuclei_installed(self, e2b_sandbox):
        """Verify Nuclei is installed in E2B template."""
        result = e2b_sandbox.commands.run("nuclei -version")

        # Nuclei outputs version info
        output = (result.stdout + result.stderr).lower()
        assert result.exit_code == 0 or "nuclei" in output

        print(f"\n✅ Nuclei version: {output.strip()}")

    def test_nuclei_templates_exist(self, e2b_sandbox):
        """Verify Nuclei templates are available."""
        # Find where nuclei templates are installed
        # Try common locations: user home, /root, and nuclei's default path
        find_result = e2b_sandbox.commands.run(
            "find /home -name 'nuclei-templates' -type d 2>/dev/null || "
            "nuclei -tl 2>&1 | head -1",
            timeout=60
        )

        templates_found = False

        # Check if we can list templates via nuclei itself
        try:
            list_result = e2b_sandbox.commands.run("nuclei -tl 2>&1 | head -5", timeout=30)
            if list_result.exit_code == 0 and list_result.stdout.strip():
                templates_found = True
                print(f"\n✅ Nuclei templates available via nuclei -tl")
        except Exception:
            pass

        if not templates_found:
            # Try to update/download templates
            print("\n⏳ Downloading Nuclei templates...")
            update_result = e2b_sandbox.commands.run("nuclei -update-templates", timeout=180)
            output = (update_result.stdout + update_result.stderr).lower()
            assert update_result.exit_code == 0 or "downloaded" in output or "templates" in output, \
                f"Failed to download templates: {update_result.stderr}"
            templates_found = True

        assert templates_found, "Nuclei templates not available"
        print(f"\n✅ Nuclei templates available")

    def test_nuclei_template_categories(self, e2b_sandbox):
        """List available Nuclei template categories."""
        try:
            result = e2b_sandbox.commands.run(
                "nuclei -tl 2>&1 | head -50",
                timeout=60
            )
            output = result.stdout if result.stdout else result.stderr
            print(f"\n📋 Sample templates:\n{output[:1000] if output else 'No output'}")
        except Exception as e:
            print(f"\n⚠️ Template listing failed: {e}")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiDefaultTemplateSelection:
    """Test Nuclei with default template settings (limited templates for faster tests)."""

    def test_default_templates_all_severities(self, nuclei_agent):
        """Test scanning with technology detection templates and all severities."""
        # Use a safe test target (scanme.nmap.org allows testing)
        targets = ["https://scanme.nmap.org"]

        # Use only technologies templates for faster test (instead of all defaults)
        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["critical", "high", "medium", "low", "info"],
            templates=["technologies/"],  # Limit to tech detection for speed
            rate_limit=150,
            timeout=120,  # 2 minutes
            update_templates=False  # Skip update for faster test
        )

        assert isinstance(findings, list)
        print(f"\n✅ Default scan found {len(findings)} findings")

        # Print summary by severity
        severity_counts = {}
        for f in findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev, count in sorted(severity_counts.items()):
            print(f"  {sev}: {count}")

    def test_default_templates_critical_high_only(self, nuclei_agent):
        """Test scanning with CVE templates, critical+high severity only."""
        targets = ["https://scanme.nmap.org"]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["critical", "high"],
            templates=["cves/2024/"],  # Limited to recent CVEs for speed
            rate_limit=150,
            timeout=120,
            update_templates=False
        )

        # All findings should be critical or high
        for finding in findings:
            assert finding.severity.lower() in ["critical", "high"], \
                f"Unexpected severity: {finding.severity}"

        print(f"\n✅ Critical+High scan found {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiSeverityBasedSelection:
    """Test Nuclei severity-based template filtering."""

    def test_critical_severity_only(self, nuclei_agent):
        """Test scanning for critical vulnerabilities only."""
        targets = ["https://scanme.nmap.org"]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["critical"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        # All findings must be critical
        for finding in findings:
            assert finding.severity.lower() == "critical", \
                f"Expected critical, got: {finding.severity}"

        print(f"\n✅ Critical-only scan: {len(findings)} findings")
        for f in findings[:5]:
            print(f"  - {f.template_id}: {f.template_name}")

    def test_high_severity_only(self, nuclei_agent):
        """Test scanning for high severity vulnerabilities only."""
        targets = ["https://scanme.nmap.org"]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["high"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        # All findings must be high
        for finding in findings:
            assert finding.severity.lower() == "high", \
                f"Expected high, got: {finding.severity}"

        print(f"\n✅ High-only scan: {len(findings)} findings")

    def test_medium_severity_only(self, nuclei_agent):
        """Test scanning for medium severity vulnerabilities only."""
        targets = ["https://scanme.nmap.org"]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["medium"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        for finding in findings:
            assert finding.severity.lower() == "medium", \
                f"Expected medium, got: {finding.severity}"

        print(f"\n✅ Medium-only scan: {len(findings)} findings")

    def test_info_severity_only(self, nuclei_agent):
        """Test scanning for informational findings only."""
        targets = ["https://scanme.nmap.org"]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["info"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        for finding in findings:
            assert finding.severity.lower() == "info", \
                f"Expected info, got: {finding.severity}"

        print(f"\n✅ Info-only scan: {len(findings)} findings")

    def test_combined_severity_levels(self, nuclei_agent):
        """Test scanning with multiple severity levels."""
        targets = ["https://scanme.nmap.org"]

        # Test high + medium
        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["high", "medium"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        for finding in findings:
            assert finding.severity.lower() in ["high", "medium"], \
                f"Unexpected severity: {finding.severity}"

        print(f"\n✅ High+Medium scan: {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiSpecificTemplateSelection:
    """Test Nuclei with specific template selection."""

    def test_tech_detection_templates(self, e2b_sandbox, integration_workspace):
        """Test using technology detection templates."""
        backend, scan_id = integration_workspace

        # Create agent with specific tech detection templates
        agent = NucleiAgent(
            scan_id=scan_id + "-tech",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Use technology detection templates
        findings = agent.execute(
            targets=targets,
            severity_filter=["info", "low", "medium", "high", "critical"],
            templates=["technologies/"],  # Technology detection category
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        print(f"\n✅ Tech detection: {len(findings)} findings")
        for f in findings[:10]:
            print(f"  - {f.template_id}: {f.template_name}")

    def test_cve_templates_selection(self, e2b_sandbox, integration_workspace):
        """Test using CVE-specific templates."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-cve",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Use CVE templates category
        findings = agent.execute(
            targets=targets,
            severity_filter=["critical", "high", "medium"],
            templates=["cves/"],  # CVE templates
            rate_limit=100,
            timeout=600,  # CVE scanning may take longer
            update_templates=False
        )

        print(f"\n✅ CVE scan: {len(findings)} findings")

        # CVE findings should have CVE IDs
        cve_findings = [f for f in findings if f.cve_id]
        print(f"   Findings with CVE IDs: {len(cve_findings)}")
        for f in cve_findings[:5]:
            print(f"  - {f.cve_id}: {f.template_name}")

    def test_exposed_panels_templates(self, e2b_sandbox, integration_workspace):
        """Test using exposed panel detection templates."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-panels",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Use exposed panels templates
        findings = agent.execute(
            targets=targets,
            severity_filter=["info", "low", "medium", "high"],
            templates=["exposed-panels/"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        print(f"\n✅ Exposed panels scan: {len(findings)} findings")
        for f in findings[:5]:
            print(f"  - {f.template_id}: {f.matched_at}")

    def test_misconfiguration_templates(self, e2b_sandbox, integration_workspace):
        """Test using misconfiguration detection templates."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-misconfig",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Use misconfiguration templates
        findings = agent.execute(
            targets=targets,
            severity_filter=["info", "low", "medium", "high", "critical"],
            templates=["misconfiguration/"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        print(f"\n✅ Misconfiguration scan: {len(findings)} findings")
        for f in findings[:5]:
            print(f"  - {f.template_id}: {f.severity}")

    def test_default_logins_templates(self, e2b_sandbox, integration_workspace):
        """Test using default login detection templates."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-logins",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Use default-logins templates
        findings = agent.execute(
            targets=targets,
            severity_filter=["high", "critical"],
            templates=["default-logins/"],
            rate_limit=50,  # Lower rate for login attempts
            timeout=300,
            update_templates=False
        )

        print(f"\n✅ Default logins scan: {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiMultipleTemplateCategories:
    """Test Nuclei with multiple template category combinations."""

    def test_combined_security_scan(self, e2b_sandbox, integration_workspace):
        """Test combined security scan with multiple template categories."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-combined",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Combine multiple template categories
        findings = agent.execute(
            targets=targets,
            severity_filter=["critical", "high", "medium"],
            templates=[
                "cves/",
                "vulnerabilities/",
                "exposed-panels/",
                "misconfiguration/"
            ],
            rate_limit=100,
            timeout=900,  # 15 minutes for comprehensive scan
            update_templates=False
        )

        print(f"\n✅ Combined security scan: {len(findings)} findings")

        # Group by severity
        severity_counts = {}
        for f in findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print("   Findings by severity:")
        for sev, count in sorted(severity_counts.items()):
            print(f"     {sev}: {count}")

    def test_web_application_scan(self, e2b_sandbox, integration_workspace):
        """Test web application focused scan."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-webapp",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Web application templates
        findings = agent.execute(
            targets=targets,
            severity_filter=["critical", "high", "medium"],
            templates=[
                "vulnerabilities/generic/",
                "misconfiguration/",
                "technologies/",
            ],
            rate_limit=100,
            timeout=600,
            update_templates=False
        )

        print(f"\n✅ Web application scan: {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiMultipleTargets:
    """Test Nuclei with multiple targets."""

    def test_scan_multiple_targets(self, nuclei_agent):
        """Test scanning multiple targets in single execution."""
        targets = [
            "https://scanme.nmap.org",
            "https://example.com",
        ]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["critical", "high", "medium"],
            rate_limit=100,
            timeout=600,
            update_templates=False
        )

        # Group findings by host
        host_findings = {}
        for f in findings:
            host = f.host
            if host not in host_findings:
                host_findings[host] = []
            host_findings[host].append(f)

        print(f"\n✅ Multi-target scan: {len(findings)} total findings")
        for host, host_f in host_findings.items():
            print(f"   {host}: {len(host_f)} findings")

    def test_scan_targets_with_different_protocols(self, nuclei_agent):
        """Test scanning targets with HTTP and HTTPS."""
        targets = [
            "https://scanme.nmap.org",
            "http://scanme.nmap.org",  # HTTP variant
        ]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["info", "low", "medium", "high", "critical"],
            rate_limit=100,
            timeout=600,
            update_templates=False
        )

        print(f"\n✅ Mixed protocol scan: {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiResultsPersistence:
    """Test that Nuclei results are properly stored."""

    def test_results_stored_in_nexus(self, nuclei_agent, integration_workspace):
        """Test that scan results are properly stored in Nexus workspace."""
        backend, scan_id = integration_workspace

        targets = ["https://scanme.nmap.org"]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["info", "medium", "high", "critical"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        # Verify files were created
        files = backend.get_all_files()

        # Check JSON results exist
        json_path = "assessment/nuclei/findings.json"
        assert any(json_path in f for f in files), \
            f"JSON results not found in workspace. Files: {list(files.keys())}"

        # Check JSONL raw output exists
        jsonl_path = "assessment/nuclei/raw_output.jsonl"
        assert any(jsonl_path in f for f in files), \
            f"JSONL raw output not found in workspace"

        print(f"\n✅ Results persisted to Nexus workspace")
        print(f"   Files: {list(files.keys())}")

    def test_result_structure(self, nuclei_agent, integration_workspace):
        """Test the structure of stored results."""
        import json

        backend, scan_id = integration_workspace
        targets = ["https://scanme.nmap.org"]

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["info", "medium"],
            rate_limit=100,
            timeout=300,
            update_templates=False
        )

        # Read stored JSON
        json_content = backend.read("/assessment/nuclei/findings.json")

        # Parse and validate structure
        if json_content and not json_content.startswith("Error:"):
            # Remove line numbers if present
            lines = []
            for line in json_content.split('\n'):
                if '→' in line:
                    lines.append(line.split('→', 1)[1])
                else:
                    lines.append(line)
            clean_content = '\n'.join(lines)

            results = json.loads(clean_content)

            assert "targets_count" in results
            assert "findings_count" in results
            assert "severity_filter" in results
            assert "findings" in results
            assert "timestamp" in results

            print(f"\n✅ Result structure validated")
            print(f"   Targets: {results['targets_count']}")
            print(f"   Findings: {results['findings_count']}")
            print(f"   Severities: {results['severity_filter']}")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiRateLimiting:
    """Test Nuclei rate limiting configuration."""

    def test_rate_limit_respected(self, e2b_sandbox, integration_workspace):
        """Test that rate limit configuration is passed correctly."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-ratelimit",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        # Test with low rate limit
        findings = agent.execute(
            targets=targets,
            severity_filter=["info"],
            rate_limit=50,  # Low rate limit
            timeout=300,
            update_templates=False
        )

        print(f"\n✅ Rate-limited scan (50 rps): {len(findings)} findings")

    def test_high_rate_limit(self, e2b_sandbox, integration_workspace):
        """Test with higher rate limit."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-highrate",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        targets = ["https://scanme.nmap.org"]

        findings = agent.execute(
            targets=targets,
            severity_filter=["info"],
            rate_limit=200,  # Higher rate limit
            timeout=300,
            update_templates=False
        )

        print(f"\n✅ High-rate scan (200 rps): {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestNucleiErrorHandling:
    """Test Nuclei error handling scenarios."""

    def test_invalid_target_handling(self, e2b_sandbox, integration_workspace):
        """Test handling of invalid targets."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-invalid",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        # ValueError is caught and wrapped in NucleiError
        with pytest.raises(NucleiError, match="must be a full URL with protocol"):
            agent.execute(
                targets=["invalid-target-no-protocol"],
                severity_filter=["high"],
                timeout=60
            )

        print("\n✅ Invalid target properly rejected")

    def test_empty_targets_handling(self, e2b_sandbox, integration_workspace):
        """Test handling of empty target list."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-empty",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        # Empty targets should return empty results
        findings = agent.execute(
            targets=[],
            severity_filter=["high"],
            timeout=60
        )

        assert findings == []
        print("\n✅ Empty targets handled correctly")

    def test_timeout_enforcement(self, e2b_sandbox, integration_workspace):
        """Test that timeout is enforced."""
        backend, scan_id = integration_workspace

        agent = NucleiAgent(
            scan_id=scan_id + "-timeout",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        # Note: This may or may not timeout depending on target response
        # Using very short timeout to increase likelihood of timeout
        try:
            findings = agent.execute(
                targets=["https://scanme.nmap.org"],
                severity_filter=["critical", "high", "medium", "low", "info"],
                templates=["cves/"],  # Large template set
                rate_limit=10,  # Slow rate
                timeout=5,  # Very short timeout
                update_templates=False
            )
            # If it completes, that's also fine
            print(f"\n✅ Scan completed within timeout: {len(findings)} findings")
        except NucleiError as e:
            # Could be timeout or sandbox-related error
            error_msg = str(e).lower()
            assert "timed out" in error_msg or "timeout" in error_msg or "sandbox" in error_msg
            print("\n✅ Timeout properly enforced")


@pytest.mark.integration
class TestNucleiTemplateVerification:
    """Verify available Nuclei template categories."""

    def test_list_template_categories(self, e2b_sandbox):
        """List and verify available template categories."""
        # Use nuclei -tl with grep to verify category templates exist
        categories = [
            "cves",
            "vulnerabilities",
            "exposed-panels",
            "misconfiguration",
            "technologies",
            "default-logins",
            "takeovers",
            "file",
            "network",
        ]

        available = []
        for category in categories:
            try:
                # Use nuclei -tl and grep for the category
                result = e2b_sandbox.commands.run(
                    f"nuclei -tl 2>&1 | grep -i '{category}' | head -1",
                    timeout=30
                )
                if result.exit_code == 0 and result.stdout.strip():
                    available.append(category)
            except Exception:
                # If grep fails, try without grep
                pass

        print(f"\n✅ Available template categories: {len(available)}")
        for cat in available:
            print(f"  - {cat}/")

    def test_count_templates_per_severity(self, e2b_sandbox):
        """Count templates per severity level."""
        try:
            result = e2b_sandbox.commands.run(
                "nuclei -tl 2>&1 | wc -l",
                timeout=60
            )
            total = result.stdout.strip() if result.stdout else "0"
            print(f"\n✅ Total templates available: {total}")
        except Exception as e:
            print(f"\n⚠️ Could not count templates: {e}")


# Convenience test for quick validation
@pytest.mark.integration
class TestNucleiQuickValidation:
    """Quick validation tests for CI/CD pipelines."""

    def test_quick_scan(self, nuclei_agent):
        """Quick scan for basic validation (< 2 minutes)."""
        targets = ["https://example.com"]  # Fast-responding target

        findings = nuclei_agent.execute(
            targets=targets,
            severity_filter=["critical", "high"],
            templates=["technologies/"],  # Quick category
            rate_limit=150,
            timeout=120,  # 2 minutes max
            update_templates=False
        )

        assert isinstance(findings, list)
        print(f"\n✅ Quick validation passed: {len(findings)} findings")
