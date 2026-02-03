import fnmatch
import re
from typing import Any, Dict, List, Optional

from .config_loader import GitsecConfig, RepositoryOverride


def matches_pattern(repo_name: str, pattern: str) -> bool:
    if pattern.startswith("regex:"):
        regex = pattern[6:]
        try:
            return bool(re.match(regex, repo_name))
        except re.error:
            return repo_name == pattern
    
    return fnmatch.fnmatch(repo_name, pattern)


def should_include_repository(
    repo_name: str,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None
) -> bool:
    if include_patterns:
        if not any(matches_pattern(repo_name, pattern) for pattern in include_patterns):
            return False
    
    if exclude_patterns:
        if any(matches_pattern(repo_name, pattern) for pattern in exclude_patterns):
            return False
    
    return True


def filter_repositories(
    repositories: List[Dict[str, Any]],
    config: Optional[GitsecConfig] = None
) -> List[Dict[str, Any]]:

    if not config or not config.repositories:
        return sorted(repositories, key=lambda r: r.get("pushed_at", ""), reverse=True)
    
    repo_config = config.repositories
    
    include_patterns = repo_config.include
    exclude_patterns = repo_config.exclude
    
    filtered = []
    for repo in repositories:
        repo_full_name = repo.get("full_name", "")
        if should_include_repository(repo_full_name, include_patterns, exclude_patterns):
            filtered.append(repo)
    
    sort_by = repo_config.sort_by or "pushed_at"
    reverse = True
    
    if sort_by == "name":
        filtered = sorted(filtered, key=lambda r: r.get("name", "").lower())
        reverse = False
    elif sort_by == "created_at":
        filtered = sorted(filtered, key=lambda r: r.get("created_at", ""), reverse=reverse)
    elif sort_by == "updated_at":
        filtered = sorted(filtered, key=lambda r: r.get("updated_at", ""), reverse=reverse)
    else:
        filtered = sorted(filtered, key=lambda r: r.get("pushed_at", ""), reverse=reverse)
    
    max_count = repo_config.max_count
    if max_count is not None and max_count > 0:
        filtered = filtered[:max_count]
    
    return filtered


def get_repository_override(
    repo_name: str,
    config: Optional[GitsecConfig] = None
) -> Optional[RepositoryOverride]:
    if not config or not config.repository_overrides:
        return None
    
    if repo_name in config.repository_overrides:
        return config.repository_overrides[repo_name]
    
    if "/" in repo_name:
        repo_short = repo_name.split("/", 1)[1]
        if repo_short in config.repository_overrides:
            return config.repository_overrides[repo_short]
    
    return None


def should_skip_secrets_scanning(
    repo_name: str,
    config: Optional[GitsecConfig] = None
) -> bool:
    if config and config.secrets_scanning and not config.secrets_scanning.enabled:
        return True
    
    override = get_repository_override(repo_name, config)
    if override and override.skip_secrets is not None:
        return override.skip_secrets
    
    return False


def should_skip_dependencies_scanning(
    repo_name: str,
    config: Optional[GitsecConfig] = None
) -> bool:
    if config and config.dependencies_scanning and not config.dependencies_scanning.enabled:
        return True
    
    override = get_repository_override(repo_name, config)
    if override and override.skip_dependencies is not None:
        return override.skip_dependencies
    
    return False


def get_enabled_security_modules(
    repo_name: Optional[str] = None,
    config: Optional[GitsecConfig] = None,
    default_modules: Optional[List[str]] = None
) -> Optional[List[str]]:
    if repo_name:
        override = get_repository_override(repo_name, config)
        if override and override.enabled_modules:
            return override.enabled_modules
    
    if config and config.security_checks and config.security_checks.enabled_modules:
        return config.security_checks.enabled_modules
    
    return default_modules


def get_disabled_security_modules(
    repo_name: Optional[str] = None,
    config: Optional[GitsecConfig] = None
) -> List[str]:
    disabled = []
    
    if config and config.security_checks and config.security_checks.disabled_modules:
        disabled.extend(config.security_checks.disabled_modules)
    
    if repo_name:
        override = get_repository_override(repo_name, config)
        if override and override.disabled_modules:
            disabled.extend(override.disabled_modules)
    
    return disabled


def get_repository_branch(
    repo_name: str,
    config: Optional[GitsecConfig] = None,
    default_branch: Optional[str] = None
) -> Optional[str]:
    override = get_repository_override(repo_name, config)
    if override and override.branch:
        return override.branch
    
    if config and config.default_branch:
        return config.default_branch
    
    return default_branch
