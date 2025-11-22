#!/usr/bin/env python3
"""Quick test to verify GCS integration."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config import get_nexus_fs
from src.agents.backends.nexus_backend import NexusBackend

print("🔍 Testing GCS Integration")
print("=" * 60)

# Initialize Nexus with GCS
nx = get_nexus_fs()
print(f"✅ Backend Type: {type(nx.backend).__name__}")
print(f"✅ GCS Bucket: {nx.backend.bucket_name}")
print(f"✅ Versioning: {'enabled' if nx.backend.versioning_enabled else 'disabled'}")
print()

# Create test workspace
backend = NexusBackend("gcs-test-scan", "gcs-test-team", nx)
print(f"✅ Created workspace: gcs-test-team/gcs-test-scan")
print()

# Write test file
test_content = "Hello from ThreatWeaver GCS test!"
result = backend.write("/test.txt", test_content)

if result.error:
    print(f"❌ Write failed: {result.error}")
    sys.exit(1)

print(f"✅ Wrote test file: {result.path}")
print()

# Read it back
content = backend.read("/test.txt", limit=999999)
if content.startswith("Error:"):
    print(f"❌ Read failed: {content}")
    sys.exit(1)

# Strip line numbers
if "→" in content:
    content = content.split("→", 1)[1]

print(f"✅ Read test file: {repr(content)}")
print()

# List files
files = backend.get_all_files()
print(f"✅ Files in workspace: {len(files)}")
for path in files.keys():
    print(f"  - {path}")
print()

print("🎉 GCS integration test passed!")
print()
print("Storage location:")
print(f"  gs://{nx.backend.bucket_name}/gcs-test-team/gcs-test-scan/test.txt")
