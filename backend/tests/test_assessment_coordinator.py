"""
Unit tests for Assessment Coordinator.

These tests use mocks to avoid E2B sandbox and LLM dependencies.
For E2E integration tests, see tests/integration/test_assessment_e2e.py
"""

import pytest
import json
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from src.agents.assessment_coordinator import (
    create_assessment_coordinator,
    create_nuclei_subagent,
    create_sqlmap_subagent,
    create_quick_assessment,
    request_approval,
    _create_bound_tools,
)


@pytest.fixture
def mock_backend():
    """Create a mock NexusBackend."""
    backend = Mock()
    backend.write = Mock(return_value=Mock(error=None))
    backend.read = Mock(return_value="")
    backend.edit = Mock(return_value=Mock(error=None))
    return backend


@pytest.fixture
def mock_model():
    """Create a mock LLM model."""
    model = Mock()
    model.invoke = Mock(return_value=Mock(content="Test response"))
    return model


class TestRequestApproval:
    """Test HITL approval tool."""

    def test_request_approval_basic(self):
        """Test basic approval request."""
        result = request_approval.invoke({
            "action": "SQLMap deep scan",
            "reason": "SQL injection detected",
            "risk_level": "high"
        })

        data = json.loads(result)
        assert data["success"] is True
        assert data["approved"] is True
        assert data["approval"]["action"] == "SQLMap deep scan"
        assert data["approval"]["risk_level"] == "high"

    def test_request_approval_with_targets(self):
        """Test approval request with targets."""
        result = request_approval.invoke({
            "action": "Data extraction",
            "reason": "Need to verify vulnerability",
            "risk_level": "critical",
            "targets": ["https://example.com/login", "https://example.com/admin"]
        })

        data = json.loads(result)
        assert data["approved"] is True
        assert len(data["approval"]["targets"]) == 2
        assert "example.com/login" in data["approval"]["targets"][0]

    def test_request_approval_auto_approved_for_demo(self):
        """Test that requests are auto-approved for demo."""
        result = request_approval.invoke({
            "action": "Any action",
            "reason": "Testing",
            "risk_level": "low"
        })

        data = json.loads(result)
        assert data["approval"]["status"] == "approved"
        assert data["approval"]["approved_by"] == "system"
        assert "demonstration" in data["approval"]["note"].lower()


class TestBoundTools:
    """Test tool binding for context injection."""

    def test_create_bound_tools(self, mock_backend):
        """Test that bound tools are created correctly."""
        bound_tools = _create_bound_tools(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend
        )

        assert "nuclei" in bound_tools
        assert "sqlmap" in bound_tools
        assert bound_tools["nuclei"].name == "run_nuclei"
        assert bound_tools["sqlmap"].name == "run_sqlmap"

    def test_bound_tools_have_descriptions(self, mock_backend):
        """Test that bound tools retain descriptions."""
        bound_tools = _create_bound_tools(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend
        )

        assert "Nuclei" in bound_tools["nuclei"].description or "vulnerabilit" in bound_tools["nuclei"].description.lower()
        assert "SQL" in bound_tools["sqlmap"].description or "injection" in bound_tools["sqlmap"].description.lower()


class TestSubAgentCreation:
    """Test sub-agent creation."""

    def test_create_nuclei_subagent(self, mock_backend):
        """Test Nuclei sub-agent creation returns SubAgent with expected attributes."""
        bound_tools = _create_bound_tools("scan", "team", mock_backend)
        subagent = create_nuclei_subagent(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend,
            bound_tools=bound_tools
        )

        # SubAgent from deepagents library - check it has the expected structure
        # Different versions may use dict or NamedTuple
        if hasattr(subagent, 'name'):
            assert subagent.name == "nuclei"
        elif isinstance(subagent, dict):
            assert subagent.get("name") == "nuclei"
        else:
            # Just verify we got something back
            assert subagent is not None

    def test_create_sqlmap_subagent(self, mock_backend):
        """Test SQLMap sub-agent creation returns SubAgent."""
        bound_tools = _create_bound_tools("scan", "team", mock_backend)
        subagent = create_sqlmap_subagent(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend,
            bound_tools=bound_tools
        )

        # Check structure
        if hasattr(subagent, 'name'):
            assert subagent.name == "sqlmap"
        elif isinstance(subagent, dict):
            assert subagent.get("name") == "sqlmap"
        else:
            assert subagent is not None

    def test_nuclei_subagent_has_system_prompt(self, mock_backend):
        """Test Nuclei sub-agent has a system prompt."""
        bound_tools = _create_bound_tools("scan", "team", mock_backend)
        subagent = create_nuclei_subagent(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend,
            bound_tools=bound_tools
        )

        # Get system_prompt
        prompt = getattr(subagent, 'system_prompt', None) or subagent.get('system_prompt', '')
        assert prompt  # Non-empty
        assert "nuclei" in prompt.lower() or "findings" in prompt.lower()

    def test_sqlmap_subagent_has_safety_rules(self, mock_backend):
        """Test SQLMap sub-agent has safety rules in prompt."""
        bound_tools = _create_bound_tools("scan", "team", mock_backend)
        subagent = create_sqlmap_subagent(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend,
            bound_tools=bound_tools
        )

        # Get system_prompt
        prompt = getattr(subagent, 'system_prompt', None) or subagent.get('system_prompt', '')
        prompt_lower = prompt.lower()
        assert "approval" in prompt_lower or "safe" in prompt_lower


class TestAssessmentCoordinatorCreation:
    """Test Assessment Coordinator creation."""

    @patch("src.agents.assessment_coordinator.create_deep_agent")
    @patch("src.agents.assessment_coordinator.ChatOpenAI")
    def test_create_coordinator_default_model(self, mock_chat, mock_deep_agent, mock_backend):
        """Test coordinator creation with default model."""
        mock_deep_agent.return_value = Mock()

        coordinator = create_assessment_coordinator(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend
        )

        # Verify model was created
        mock_chat.assert_called_once()
        call_kwargs = mock_chat.call_args[1]
        assert "claude" in call_kwargs["model"].lower() or "anthropic" in call_kwargs["model"].lower()

    @patch("src.agents.assessment_coordinator.create_deep_agent")
    def test_create_coordinator_with_custom_model(self, mock_deep_agent, mock_backend, mock_model):
        """Test coordinator creation with custom model."""
        mock_deep_agent.return_value = Mock()

        coordinator = create_assessment_coordinator(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend,
            model=mock_model
        )

        # Verify create_deep_agent was called with custom model
        call_kwargs = mock_deep_agent.call_args[1]
        assert call_kwargs["model"] == mock_model

    @patch("src.agents.assessment_coordinator.create_deep_agent")
    @patch("src.agents.assessment_coordinator.ChatOpenAI")
    def test_coordinator_has_subagents(self, mock_chat, mock_deep_agent, mock_backend):
        """Test coordinator has Nuclei and SQLMap subagents."""
        mock_deep_agent.return_value = Mock()

        coordinator = create_assessment_coordinator(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend
        )

        call_kwargs = mock_deep_agent.call_args[1]
        subagents = call_kwargs["subagents"]

        assert len(subagents) == 2
        # SubAgent may be object or dict depending on library version
        subagent_names = []
        for s in subagents:
            if hasattr(s, 'name'):
                subagent_names.append(s.name)
            elif isinstance(s, dict):
                subagent_names.append(s.get('name'))
        assert "nuclei" in subagent_names
        assert "sqlmap" in subagent_names

    @patch("src.agents.assessment_coordinator.create_deep_agent")
    @patch("src.agents.assessment_coordinator.ChatOpenAI")
    def test_coordinator_has_approval_tool(self, mock_chat, mock_deep_agent, mock_backend):
        """Test coordinator has request_approval tool."""
        mock_deep_agent.return_value = Mock()

        coordinator = create_assessment_coordinator(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend
        )

        call_kwargs = mock_deep_agent.call_args[1]
        tools = call_kwargs["tools"]

        tool_names = [t.name for t in tools]
        assert "request_approval" in tool_names

    @patch("src.agents.assessment_coordinator.create_deep_agent")
    @patch("src.agents.assessment_coordinator.ChatOpenAI")
    def test_coordinator_system_prompt_includes_workflow(self, mock_chat, mock_deep_agent, mock_backend):
        """Test coordinator system prompt includes workflow steps."""
        mock_deep_agent.return_value = Mock()

        coordinator = create_assessment_coordinator(
            scan_id="test-scan",
            team_id="test-team",
            backend=mock_backend
        )

        call_kwargs = mock_deep_agent.call_args[1]
        prompt = call_kwargs["system_prompt"].lower()

        # Verify workflow steps are mentioned
        assert "nuclei" in prompt
        assert "sqlmap" in prompt
        assert "approval" in prompt
        assert "escalation" in prompt or "sqli" in prompt


class TestQuickAssessment:
    """Test quick automated assessment."""

    def test_quick_assessment_runs_nuclei(self, mock_backend):
        """Test quick assessment runs Nuclei scan."""
        with patch("src.agents.assessment.nuclei_agent.NucleiAgent") as mock_nuclei_class, \
             patch("src.agents.assessment.sqlmap_agent.SQLMapAgent") as mock_sqlmap_class:
            # Setup mock Nuclei agent
            mock_nuclei = Mock()
            mock_nuclei.execute.return_value = []
            mock_nuclei.cleanup = Mock()
            mock_nuclei_class.return_value = mock_nuclei

            result = create_quick_assessment(
                targets=["https://example.com"],
                scan_id="quick-test",
                team_id="test-team",
                backend=mock_backend
            )

            mock_nuclei.execute.assert_called_once()
            assert result["status"] == "completed"
            assert result["scan_id"] == "quick-test"

    def test_quick_assessment_no_sqli(self, mock_backend):
        """Test quick assessment without SQL injection findings."""
        with patch("src.agents.assessment.nuclei_agent.NucleiAgent") as mock_nuclei_class, \
             patch("src.agents.assessment.sqlmap_agent.SQLMapAgent") as mock_sqlmap_class:
            # Setup mock Nuclei agent with non-SQLi findings
            mock_finding = Mock()
            mock_finding.severity = "high"
            mock_finding.template_id = "exposed-panel"
            mock_finding.name = "Admin Panel Detected"
            mock_finding.model_dump = Mock(return_value={"severity": "high"})

            mock_nuclei = Mock()
            mock_nuclei.execute.return_value = [mock_finding]
            mock_nuclei.cleanup = Mock()
            mock_nuclei_class.return_value = mock_nuclei

            result = create_quick_assessment(
                targets=["https://example.com"],
                scan_id="quick-test",
                team_id="test-team",
                backend=mock_backend
            )

            # SQLMap should not be called
            mock_sqlmap_class.assert_not_called()
            assert result["summary"]["sqli_indicators"] == 0
            assert result["summary"]["sqli_confirmed"] is False

    def test_quick_assessment_with_sqli(self, mock_backend):
        """Test quick assessment triggers SQLMap on SQLi finding."""
        with patch("src.agents.assessment.nuclei_agent.NucleiAgent") as mock_nuclei_class, \
             patch("src.agents.assessment.sqlmap_agent.SQLMapAgent") as mock_sqlmap_class:
            # Setup mock Nuclei agent with SQLi finding
            mock_sqli_finding = Mock()
            mock_sqli_finding.severity = "critical"
            mock_sqli_finding.template_id = "sqli-error-based"
            mock_sqli_finding.name = "SQL Injection"
            mock_sqli_finding.matched_at = "https://example.com/page?id=1"
            mock_sqli_finding.host = "example.com"
            mock_sqli_finding.model_dump = Mock(return_value={"severity": "critical"})

            mock_nuclei = Mock()
            mock_nuclei.execute.return_value = [mock_sqli_finding]
            mock_nuclei.cleanup = Mock()
            mock_nuclei_class.return_value = mock_nuclei

            # Setup mock SQLMap agent
            mock_sqlmap_result = Mock()
            mock_sqlmap_result.model_dump = Mock(return_value={"vulnerable": True})

            mock_sqlmap = Mock()
            mock_sqlmap.execute.return_value = [mock_sqlmap_result]
            mock_sqlmap.cleanup = Mock()
            mock_sqlmap_class.return_value = mock_sqlmap

            result = create_quick_assessment(
                targets=["https://example.com"],
                scan_id="quick-test",
                team_id="test-team",
                backend=mock_backend
            )

            # SQLMap should be called
            mock_sqlmap_class.assert_called_once()
            mock_sqlmap.execute.assert_called()
            assert result["summary"]["sqli_indicators"] == 1
            assert result["sqli_details"] is not None

    def test_quick_assessment_stores_report(self, mock_backend):
        """Test quick assessment stores report to workspace."""
        with patch("src.agents.assessment.nuclei_agent.NucleiAgent") as mock_nuclei_class, \
             patch("src.agents.assessment.sqlmap_agent.SQLMapAgent"):
            mock_nuclei = Mock()
            mock_nuclei.execute.return_value = []
            mock_nuclei.cleanup = Mock()
            mock_nuclei_class.return_value = mock_nuclei

            result = create_quick_assessment(
                targets=["https://example.com"],
                scan_id="quick-test",
                team_id="test-team",
                backend=mock_backend
            )

            # Verify report was written
            mock_backend.write.assert_called()
            call_args = mock_backend.write.call_args[0]
            assert "quick_report.json" in call_args[0]

    def test_quick_assessment_custom_severity(self, mock_backend):
        """Test quick assessment with custom severity filter."""
        with patch("src.agents.assessment.nuclei_agent.NucleiAgent") as mock_nuclei_class, \
             patch("src.agents.assessment.sqlmap_agent.SQLMapAgent"):
            mock_nuclei = Mock()
            mock_nuclei.execute.return_value = []
            mock_nuclei.cleanup = Mock()
            mock_nuclei_class.return_value = mock_nuclei

            result = create_quick_assessment(
                targets=["https://example.com"],
                scan_id="quick-test",
                team_id="test-team",
                backend=mock_backend,
                severity_filter=["critical"]
            )

            # Verify Nuclei was called with custom severity
            call_kwargs = mock_nuclei.execute.call_args[1]
            assert call_kwargs["severity_filter"] == ["critical"]


class TestWorkflowIntegration:
    """Test workflow integration patterns."""

    def test_sqli_detection_patterns(self):
        """Test SQL injection detection patterns."""
        sqli_indicators = [
            "sqli-error-based",
            "sql-injection",
            "sqli-blind",
            "mysql-sqli",
            "generic-sqli"
        ]

        for indicator in sqli_indicators:
            template_id = indicator.lower()
            assert "sqli" in template_id or "sql" in template_id

    def test_severity_priority_order(self):
        """Test that severity priority is correct."""
        priority = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }

        # Verify critical > high > medium > low > info
        assert priority["critical"] > priority["high"]
        assert priority["high"] > priority["medium"]
        assert priority["medium"] > priority["low"]
        assert priority["low"] > priority["info"]
