"""
Nexus Backend for DeepAgents.

This module implements DeepAgents' BackendProtocol using Nexus filesystem with S3.
Provides file operations for agent workspaces backed by S3 (production) or local storage (dev).

Reference:
- DeepAgents: https://github.com/langchain-ai/deepagents
- Nexus: https://github.com/nexi-lab/nexus
- Syntar implementation: /Users/tafeng/syntar/backend/src/reasoning_engine/backends/nexus_backend.py
"""

import fnmatch
from typing import Optional

from deepagents.backends.protocol import (
    BackendProtocol,
    EditResult,
    FileInfo,
    GrepMatch,
    WriteResult,
)
from nexus.core.nexus_fs import NexusFS


class NexusBackend(BackendProtocol):
    """
    DeepAgents backend using Nexus filesystem with S3 or local storage.

    This backend provides file I/O operations for a single scan workspace,
    storing files in S3 (production) or local filesystem (development) via Nexus.

    Storage:
    - Production: s3://threatweaver-scans/{team_id}/{scan_id}/
    - Development: ./nexus-data/{team_id}/{scan_id}/

    Example:
        >>> from config.nexus_config import get_nexus_fs
        >>> backend = NexusBackend("scan-123", "team-abc", get_nexus_fs())
        >>> result = backend.write("/recon/results.json", '{"subdomains": [...]}')
    """

    def __init__(self, scan_id: str, team_id: str, nexus_fs: NexusFS):
        """
        Initialize backend for a scan workspace.

        Args:
            scan_id: Scan identifier (e.g., "scan-20251118-123456")
            team_id: Team identifier (e.g., "team-abc123") for multi-tenancy
            nexus_fs: NexusFS instance (configured with S3/local connector)
        """
        self.scan_id = scan_id
        self.team_id = team_id
        self.base_path = f"/{team_id}/{scan_id}"
        self.nx = nexus_fs

        # Create workspace directory
        self.nx.mkdir(self.base_path, parents=True, exist_ok=True)

    def _to_nexus_path(self, agent_path: str) -> str:
        """
        Convert agent-relative path to Nexus path.

        Args:
            agent_path: Path relative to scan workspace (e.g., "/recon/results.json")

        Returns:
            Full Nexus path (e.g., "/team-abc123/scan-123456/recon/results.json")
        """
        if agent_path.startswith("/"):
            return f"{self.base_path}{agent_path}"
        else:
            return f"{self.base_path}/{agent_path}"

    def read(self, file_path: str, offset: int = 0, limit: int = 2000) -> str:
        """
        Read file content with line numbers (DeepAgents format).

        Args:
            file_path: Path to file (relative to scan workspace)
            offset: Line number to start from (0-indexed)
            limit: Maximum lines to read

        Returns:
            Content with line numbers like "     1→content"
            or error message if file not found
        """
        nexus_path = self._to_nexus_path(file_path)

        try:
            content_bytes = self.nx.read(nexus_path)
            content = content_bytes.decode("utf-8")

            # Add line numbers (DeepAgents format)
            lines = content.splitlines()[offset : offset + limit]
            numbered = [f"{i+offset+1:6d}→{line}" for i, line in enumerate(lines)]
            return "\n".join(numbered)

        except Exception as e:
            return f"Error reading {file_path}: {str(e)}"

    def write(self, file_path: str, content: str) -> WriteResult:
        """
        Write new file (create-only semantics).

        Args:
            file_path: Path to file
            content: File content

        Returns:
            WriteResult with error=None on success, error message on failure
        """
        nexus_path = self._to_nexus_path(file_path)

        # Check if file exists (create-only semantics)
        try:
            self.nx.read(nexus_path)
            return WriteResult(
                error=f"File already exists: {file_path}. Use edit() to modify.",
                path=None,
                files_update=None,
            )
        except Exception:
            # File doesn't exist, proceed with write
            pass

        try:
            # Ensure parent directory exists
            parent = "/".join(nexus_path.split("/")[:-1])
            if parent:
                self.nx.mkdir(parent, parents=True, exist_ok=True)

            # Write file to S3/local via Nexus
            self.nx.write(nexus_path, content.encode("utf-8"))

            return WriteResult(
                error=None,  # Success
                path=file_path,
                files_update=None,  # External storage (S3/local), not in-memory
            )

        except Exception as e:
            return WriteResult(
                error=f"Failed to write {file_path}: {str(e)}",
                path=None,
                files_update=None,
            )

    def edit(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
    ) -> EditResult:
        """
        Edit existing file by replacing string occurrences.

        Args:
            file_path: Path to file
            old_string: Text to find and replace
            new_string: Replacement text
            replace_all: If True, replace all occurrences; if False, replace first only

        Returns:
            EditResult with error=None on success
        """
        nexus_path = self._to_nexus_path(file_path)

        try:
            # Read current content
            content_bytes = self.nx.read(nexus_path)
            content = content_bytes.decode("utf-8")

            # Check if old_string exists
            if old_string not in content:
                return EditResult(
                    error=f"Text not found in {file_path}: {old_string[:50]}...",
                    path=None,
                    files_update=None,
                    occurrences=None,
                )

            # Replace occurrences
            if replace_all:
                occurrences = content.count(old_string)
                new_content = content.replace(old_string, new_string)
            else:
                occurrences = 1
                new_content = content.replace(old_string, new_string, 1)

            # Write back to S3/local via Nexus
            self.nx.write(nexus_path, new_content.encode("utf-8"))

            return EditResult(
                error=None,  # Success
                path=file_path,
                files_update=None,  # External storage
                occurrences=occurrences,
            )

        except Exception as e:
            return EditResult(
                error=f"Failed to edit {file_path}: {str(e)}",
                path=None,
                files_update=None,
                occurrences=None,
            )

    def ls_info(self, path: str) -> list[FileInfo]:
        """
        List files and directories with metadata.

        Args:
            path: Directory path (relative to scan workspace)

        Returns:
            List of FileInfo dicts
        """
        nexus_path = self._to_nexus_path(path)

        try:
            paths = self.nx.list(nexus_path, recursive=False)

            result = []
            for file_path in paths:
                # Directories end with /
                is_dir = file_path.endswith("/")

                # Get relative path
                rel_path = file_path.replace(nexus_path + "/", "").replace(nexus_path, "")

                # Try to get size (0 for directories)
                size = 0
                if not is_dir:
                    try:
                        content = self.nx.read(file_path)
                        size = len(content)
                    except Exception:
                        pass

                # FileInfo is a TypedDict, create dict
                file_info: FileInfo = {
                    "path": rel_path,
                    "is_dir": is_dir,
                    "size": size,
                }

                result.append(file_info)

            return result

        except Exception:
            return []

    def grep_raw(
        self,
        pattern: str,
        path: Optional[str] = None,
        glob: Optional[str] = None,
    ) -> list[GrepMatch] | str:
        """
        Search for text within files (like Unix grep).

        Args:
            pattern: Text pattern to search for (case-insensitive)
            path: Optional directory path to search in
            glob: Optional file glob pattern (e.g., "*.md")

        Returns:
            List of GrepMatch dicts or error string
        """
        try:
            # Determine search path
            search_path = self._to_nexus_path(path) if path else self.base_path

            # Get all files recursively
            all_paths = self.nx.list(search_path, recursive=True)

            # Filter by glob pattern if provided
            if glob:
                matching_files = [
                    p
                    for p in all_paths
                    if not p.endswith("/") and fnmatch.fnmatch(p.split("/")[-1], glob)
                ]
            else:
                matching_files = [p for p in all_paths if not p.endswith("/")]

            results: list[GrepMatch] = []
            for file_path in matching_files:
                try:
                    content_bytes = self.nx.read(file_path)
                    content = content_bytes.decode("utf-8")

                    # Find matching lines (case-insensitive)
                    lines = content.split("\n")
                    for line_num, line in enumerate(lines, start=1):
                        if pattern.lower() in line.lower():
                            # Get relative path
                            rel_path = file_path.replace(self.base_path + "/", "")

                            # GrepMatch is a TypedDict
                            match: GrepMatch = {
                                "path": rel_path,
                                "line": line_num,
                                "text": line,
                            }
                            results.append(match)

                except Exception:
                    continue

            return results if results else "No matches found"

        except Exception as e:
            return f"Error searching: {str(e)}"

    def glob_info(self, pattern: str, path: str = "/") -> list[FileInfo]:
        """
        Glob file matching returning FileInfo dicts.

        Args:
            pattern: Glob pattern (e.g., "*.md", "**/recon/*")
            path: Base directory to search in (default: "/")

        Returns:
            List of FileInfo dicts for matching files
        """
        nexus_path = self._to_nexus_path(path)

        try:
            # Get all files recursively
            all_paths = self.nx.list(nexus_path, recursive=True)

            # Match against pattern
            results = []
            for file_path in all_paths:
                rel_path = file_path.replace(self.base_path + "/", "")

                if fnmatch.fnmatch(rel_path, pattern):
                    is_dir = file_path.endswith("/")

                    # Get size
                    size = 0
                    if not is_dir:
                        try:
                            content = self.nx.read(file_path)
                            size = len(content)
                        except Exception:
                            pass

                    file_info: FileInfo = {
                        "path": rel_path,
                        "is_dir": is_dir,
                        "size": size,
                    }
                    results.append(file_info)

            return results

        except Exception:
            return []

    # Helper methods for debugging and management

    def get_all_files(self) -> dict[str, str]:
        """
        Get all files from this scan's workspace.

        Returns:
            Dict mapping file paths to contents

        Example:
            >>> backend = NexusBackend("scan-123", "team-abc", nexus_fs)
            >>> files = backend.get_all_files()
            >>> print(files.keys())
            dict_keys(['recon/subfinder/results.json', 'recon/nmap/ports.json'])
        """
        try:
            paths = self.nx.list(self.base_path, recursive=True)

            result = {}
            for path in paths:
                if not path.endswith("/"):
                    try:
                        content_bytes = self.nx.read(path)
                        content = content_bytes.decode("utf-8")

                        # Get relative path
                        rel_path = path.replace(self.base_path + "/", "")
                        result[rel_path] = content
                    except Exception:
                        continue

            return result

        except Exception:
            return {}

    def get_workspace_summary(self) -> dict:
        """
        Get summary of workspace (file count, total size, directory structure).

        Returns:
            Dict with workspace metadata

        Example:
            >>> backend.get_workspace_summary()
            {
                'scan_id': 'scan-123',
                'team_id': 'team-abc',
                'file_count': 5,
                'total_size': 12345,
                'directories': ['recon/', 'findings/']
            }
        """
        try:
            all_files = self.get_all_files()

            total_size = sum(len(content) for content in all_files.values())

            # Extract unique directories
            directories = set()
            for path in all_files.keys():
                parts = path.split("/")
                for i in range(1, len(parts)):
                    directories.add("/".join(parts[:i]) + "/")

            return {
                "scan_id": self.scan_id,
                "team_id": self.team_id,
                "file_count": len(all_files),
                "total_size": total_size,
                "directories": sorted(directories),
            }

        except Exception:
            return {
                "scan_id": self.scan_id,
                "team_id": self.team_id,
                "file_count": 0,
                "total_size": 0,
                "directories": [],
            }
