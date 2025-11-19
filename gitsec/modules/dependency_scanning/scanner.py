import base64
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from gitsec.core.depsdev_client import Advisory, DepsDevClient
from gitsec.core.github_api import GitHubClient
from gitsec.modules.dependency_scanning.dependency_parser import (
    Dependency,
    DependencyParser,
)


@dataclass
class VulnerabilityFinding:
    dependency: Dependency
    advisory: Advisory
    severity: str


@dataclass
class DeprecationFinding:
    dependency: Dependency


@dataclass
class UnpinnedDependencyFinding:
    dependency: Dependency


@dataclass
class ScanResult:
    repo: str
    total_dependencies: int
    vulnerabilities: List[VulnerabilityFinding]
    deprecations: List[DeprecationFinding]
    unpinned_dependencies: List[UnpinnedDependencyFinding]
    manifest_files: List[str]


class DependencyScanner:
    def __init__(self, github_client: Optional[GitHubClient] = None):
        self.github_client = github_client
        self.deps_client = DepsDevClient()

    def scan_repository(
        self,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        local_path: Optional[str] = None,
    ) -> Optional[ScanResult]:
        if local_path:
            return self._scan_local(local_path)
        elif owner and repo:
            return self._scan_remote(owner, repo)
        else:
            return None

    def _scan_remote(self, owner: str, repo: str) -> Optional[ScanResult]:
        """Scan a remote GitHub repository."""
        if not self.github_client:
            return None

        repo_full = f"{owner}/{repo}"

        default_branch = self._get_default_branch(owner, repo)
        if not default_branch:
            return None

        tree = self._get_repo_tree(owner, repo, default_branch)
        if not tree:
            return None

        manifest_files = self._find_manifest_files(tree)
        if not manifest_files:
            return self._empty_result(repo_full)

        manifest_contents = {}
        for path in manifest_files:
            content = self._get_file_content(owner, repo, path)
            if content:
                manifest_contents[path] = content

        return self._analyze_dependencies(repo_full, manifest_files, manifest_contents)

    def _scan_local(self, repo_path: str) -> Optional[ScanResult]:
        if not os.path.exists(repo_path):
            return None

        manifest_files = []
        manifest_patterns = DependencyParser.get_all_manifest_patterns()

        for root, _, files in os.walk(repo_path):
            if "/.git/" in root or "/node_modules/" in root:
                continue

            for filename in files:
                if filename in manifest_patterns:
                    file_path = os.path.join(root, filename)
                    relative_path = os.path.relpath(file_path, repo_path)
                    manifest_files.append(relative_path)

        if not manifest_files:
            return self._empty_result(repo_path)

        manifest_contents = {}
        for path in manifest_files:
            full_path = os.path.join(repo_path, path)
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    manifest_contents[path] = f.read()
            except Exception:
                continue

        return self._analyze_dependencies(repo_path, manifest_files, manifest_contents)

    def _analyze_dependencies(
        self,
        repo_name: str,
        manifest_files: List[str],
        manifest_contents: Dict[str, str],
    ) -> ScanResult:
        lockfiles = [
            f for f in manifest_files if f.split("/")[-1] in DependencyParser.LOCKFILES
        ]
        manifests = [
            f
            for f in manifest_files
            if f.split("/")[-1] not in DependencyParser.LOCKFILES
        ]

        deps_by_name = {}

        for lockfile_path in lockfiles:
            if lockfile_path in manifest_contents:
                deps = DependencyParser.parse_file(
                    lockfile_path, manifest_contents[lockfile_path]
                )
                for dep in deps:
                    key = (dep.ecosystem, dep.name)
                    deps_by_name[key] = dep

        for manifest_path in manifests:
            if manifest_path in manifest_contents:
                deps = DependencyParser.parse_file(
                    manifest_path, manifest_contents[manifest_path]
                )
                for dep in deps:
                    key = (dep.ecosystem, dep.name)
                    if key not in deps_by_name:
                        deps_by_name[key] = dep

        all_deps = list(deps_by_name.values())

        vulnerabilities = []
        deprecations = []
        unpinned_dependencies = []

        for dep in all_deps:
            if not dep.is_pinned:
                unpinned_dependencies.append(UnpinnedDependencyFinding(dependency=dep))

            if not dep.version:
                continue

            pkg_info = self.deps_client.get_version_info(
                dep.ecosystem, dep.name, dep.version
            )

            if not pkg_info:
                continue

            if pkg_info.is_deprecated:
                deprecations.append(DeprecationFinding(dependency=dep))

            for advisory_id in pkg_info.advisory_ids:
                advisory = self.deps_client.get_advisory(advisory_id)
                if advisory:
                    severity = self._calculate_severity(advisory.cvss3_score)
                    vuln_finding = VulnerabilityFinding(
                        dependency=dep, advisory=advisory, severity=severity
                    )
                    vulnerabilities.append(vuln_finding)

        return ScanResult(
            repo=repo_name,
            total_dependencies=len(all_deps),
            vulnerabilities=vulnerabilities,
            deprecations=deprecations,
            unpinned_dependencies=unpinned_dependencies,
            manifest_files=manifest_files,
        )

    def _empty_result(self, repo_name: str) -> ScanResult:
        return ScanResult(
            repo=repo_name,
            total_dependencies=0,
            vulnerabilities=[],
            deprecations=[],
            unpinned_dependencies=[],
            manifest_files=[],
        )

    def _get_default_branch(self, owner: str, repo: str) -> Optional[str]:
        if not self.github_client:
            return None
        try:
            repo_data = self.github_client.get(f"/repos/{owner}/{repo}")
            return repo_data.get("default_branch", "main")
        except Exception:
            return None

    def _get_repo_tree(self, owner: str, repo: str, ref: str) -> Optional[Dict]:
        if not self.github_client:
            return None
        try:
            tree = self.github_client.get(
                f"/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
            )
            return tree
        except Exception:
            return None

    def _find_manifest_files(self, tree: Dict) -> List[str]:
        manifest_patterns = DependencyParser.get_all_manifest_patterns()
        manifest_files = []

        for item in tree.get("tree", []):
            if item["type"] == "blob":
                path = item["path"]
                filename = path.split("/")[-1]
                if filename in manifest_patterns:
                    manifest_files.append(path)

        return manifest_files

    def _get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        if not self.github_client:
            return None
        try:
            file_data = self.github_client.get(f"/repos/{owner}/{repo}/contents/{path}")
            if file_data and "content" in file_data:
                return base64.b64decode(file_data["content"]).decode("utf-8")
        except Exception:
            pass
        return None

    @staticmethod
    def _calculate_severity(cvss_score: Optional[float]) -> str:
        if not cvss_score:
            return "unknown"
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"

    def close(self):
        self.deps_client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
