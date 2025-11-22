"""
Nexus filesystem configuration for ThreatWeaver.

Provides factory function to create NexusFS instances with appropriate backend
(GCS for production, local for development).

Reference:
- Nexus GitHub: https://github.com/nexi-lab/nexus
- GCS Connector: Uses direct path mapping (not CAS)
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from nexus.backends.gcs_connector import GCSConnectorBackend
from nexus.backends.local import LocalBackend
from nexus.core.nexus_fs import NexusFS

# Load .env file if it exists
load_dotenv()


def get_nexus_fs() -> NexusFS:
    """
    Create NexusFS instance with appropriate backend based on environment.

    Returns:
        NexusFS instance configured for current environment

    Environment Variables:
        - NEXUS_BACKEND: "gcs" or "local" (default: "local")
        - GCS_BUCKET_NAME: GCS bucket name (required for GCS backend)
        - GCS_PROJECT_ID: GCP project ID (optional, inferred from credentials)
        - GCS_CREDENTIALS_PATH: Path to service account JSON (optional, uses ADC)
        - NEXUS_LOCAL_PATH: Local storage path (default: "./nexus-data")
        - NEXUS_DB_PATH: SQLite metadata DB path (default: "./nexus-metadata.db")

    Storage Structure:
        Local:  ./nexus-data/{team_id}/{scan_id}/...
        GCS:    gs://threatweaver-scans/{team_id}/{scan_id}/...

    Example (Local Development):
        >>> # .env
        >>> NEXUS_BACKEND=local
        >>> NEXUS_LOCAL_PATH=./nexus-data
        >>>
        >>> # Usage
        >>> from src.config import get_nexus_fs
        >>> nx = get_nexus_fs()
        >>> nx.write("/team-123/scan-456/results.json", b"...")

    Example (GCS Production):
        >>> # .env
        >>> NEXUS_BACKEND=gcs
        >>> GCS_BUCKET_NAME=threatweaver-scans
        >>> GCS_PROJECT_ID=threatweaver-prod
        >>> GCS_CREDENTIALS_PATH=/secrets/gcs-key.json
        >>>
        >>> # Usage
        >>> nx = get_nexus_fs()
        >>> # Files stored as: gs://threatweaver-scans/{team_id}/{scan_id}/...
    """
    backend_type = os.getenv("NEXUS_BACKEND", "local").lower()

    if backend_type == "gcs":
        # GCS Backend (Production)
        bucket_name = os.getenv("GCS_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "GCS_BUCKET_NAME environment variable required for GCS backend. "
                "Set NEXUS_BACKEND=local to use local storage instead."
            )

        project_id = os.getenv("GCS_PROJECT_ID")
        credentials_path = os.getenv("GCS_CREDENTIALS_PATH")

        backend = GCSConnectorBackend(
            bucket_name=bucket_name,
            project_id=project_id,
            credentials_path=credentials_path,
            prefix="",  # No prefix, use full paths like /{team_id}/{scan_id}/
        )

    else:
        # Local Backend (Development)
        local_path = os.getenv("NEXUS_LOCAL_PATH", "./nexus-data")
        Path(local_path).mkdir(parents=True, exist_ok=True)

        backend = LocalBackend(root_path=local_path)

    # Create NexusFS with backend
    db_path = os.getenv("NEXUS_DB_PATH", "./nexus-metadata.db")

    nexus_fs = NexusFS(
        backend=backend,
        db_path=db_path,
        enable_metadata_cache=True,
        enable_content_cache=True,
        content_cache_size_mb=128,  # Cache for faster reads
        auto_parse=False,  # Don't auto-parse security tool outputs
        enforce_permissions=False,  # Disable for embedded mode (agents are trusted)
    )

    return nexus_fs
