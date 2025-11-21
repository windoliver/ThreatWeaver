"""
E2B Template Definition for ThreatWeaver Security Tools.

This template includes all security scanning tools needed for ThreatWeaver agents.
"""

from e2b import Sandbox

# Build template from our existing Dockerfile
template = Sandbox.from_dockerfile(
    dockerfile_path="./Dockerfile",
    template_name="threatweaver-security",
)

if __name__ == "__main__":
    print(f"Template created: {template.template}")
    print("Build this template with: e2b template build")
