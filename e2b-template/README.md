# ThreatWeaver E2B Custom Template

This directory contains the E2B custom template with all security tools pre-installed.

## Tools Included

- **Subfinder** - Subdomain discovery (ProjectDiscovery)
- **HTTPx** - HTTP probing and fingerprinting (ProjectDiscovery)
- **Nuclei** - Vulnerability scanner with 9000+ templates (ProjectDiscovery)
- **Nmap** - Network port scanner
- **SQLMap** - SQL injection exploitation tool

## Build Instructions

### Prerequisites

1. Install E2B CLI:
```bash
npm install -g @e2b/cli
```

2. Login to E2B:
```bash
e2b auth login
```

### Build Template

```bash
cd e2b-template

# Build the template (takes 5-10 minutes)
e2b template build

# Output will show:
# ✓ Template built successfully
# Template ID: threatweaver-security
# Use this template ID in your code
```

### Test Template

```bash
# Test the template locally
e2b template test

# This will create a sandbox and verify all tools work
```

## Usage in ThreatWeaver

Once built, update your backend `.env` file:

```bash
# E2B Configuration
SANDBOX_PROVIDER=e2b
E2B_API_KEY=your_e2b_api_key_here
E2B_TEMPLATE_ID=threatweaver-security
```

The sandbox provider will automatically use your custom template with all tools installed.

## Template Updates

When you need to update tools or add new ones:

1. Modify `e2b.Dockerfile`
2. Rebuild: `e2b template build`
3. The template ID stays the same, new sandboxes use the updated version

## Verification

Test that all tools are installed:

```python
from e2b_code_interpreter import Sandbox

sandbox = Sandbox.create(template="threatweaver-security")

# Test each tool
tools = ["subfinder -version", "httpx -version", "nuclei -version",
         "nmap --version", "sqlmap --version"]

for tool_cmd in tools:
    result = sandbox.run_code(f"subprocess.run(['{tool_cmd}'], shell=True)")
    print(f"{tool_cmd}: OK" if not result.error else f"{tool_cmd}: FAILED")

sandbox.kill()
```

## Cost Estimate

- Template build: Free (one-time)
- Sandbox creation: ~$0.01-0.05 per execution
- Compute time: ~$0.10-0.50 per hour
- Typical scan: ~$0.18 (includes all 5 tools)

## Troubleshooting

### Build fails with "Go not found"
- The Dockerfile installs Go - make sure Docker has internet access

### Template build times out
- E2B builds can take 5-10 minutes - be patient
- Check E2B dashboard for build logs

### Tools not found in sandbox
- Verify template ID matches in .env: `E2B_TEMPLATE_ID=threatweaver-security`
- Check PATH includes /root/go/bin

## Template Structure

```
e2b-template/
├── e2b.Dockerfile       # Template definition with all tools
├── e2b.toml            # E2B configuration
└── README.md           # This file
```

## Next Steps

After building the template:

1. Update `backend/.env` with template ID
2. Run tests: `pytest tests/test_sandbox.py -v`
3. Implement agents (#13-18) that use the tools
4. Deploy!
