import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator


class TargetConfig(BaseModel):
    org: Optional[str] = None
    repo: Optional[str] = None
    local_repo: Optional[str] = None

    @field_validator("repo")
    @classmethod
    def validate_repo_format(cls, v: Optional[str]) -> Optional[str]:
        if v and "/" not in v:
            raise ValueError("repo must be in 'owner/repo' format")
        return v


class RepositoriesConfig(BaseModel):
    include: Optional[List[str]] = Field(default=None, description="Patterns of repositories to include")
    exclude: Optional[List[str]] = Field(default=None, description="Patterns of repositories to exclude")
    max_count: Optional[int] = Field(default=None, description="Maximum number of repositories to scan")
    sort_by: Optional[str] = Field(default="pushed_at", description="Field to sort repositories by")


class ScanningConfig(BaseModel):
    enabled: bool = Field(default=True, description="Whether this scanning module is enabled")


class SecurityChecksConfig(BaseModel):
    enabled_modules: Optional[List[str]] = Field(default=None, description="List of modules to enable")
    disabled_modules: Optional[List[str]] = Field(default=None, description="List of modules to disable")


class RepositoryOverride(BaseModel):
    branch: Optional[str] = Field(default=None, description="Custom branch to check")
    enabled_modules: Optional[List[str]] = Field(default=None, description="Modules to run for this repo")
    disabled_modules: Optional[List[str]] = Field(default=None, description="Modules to skip for this repo")
    skip_secrets: Optional[bool] = Field(default=None, description="Skip secret scanning for this repo")
    skip_dependencies: Optional[bool] = Field(default=None, description="Skip dependency scanning for this repo")


class GitsecConfig(BaseModel):
    target: Optional[TargetConfig] = None
    base_url: Optional[str] = Field(default=None, description="GitHub API base URL")
    output_folder: Optional[str] = Field(default=None, description="Output folder for results")
    default_branch: Optional[str] = Field(default=None, description="Default branch name if not specified")
    
    secrets_scanning: Optional[ScanningConfig] = Field(default_factory=lambda: ScanningConfig())
    dependencies_scanning: Optional[ScanningConfig] = Field(default_factory=lambda: ScanningConfig())
    security_checks: Optional[SecurityChecksConfig] = None
    
    repositories: Optional[RepositoriesConfig] = None
    repository_overrides: Optional[Dict[str, RepositoryOverride]] = Field(
        default=None, 
        description="Per-repository configuration overrides"
    )


def discover_config_file(config_path: Optional[str] = None) -> Optional[Path]:
    if config_path:
        path = Path(config_path).expanduser().resolve()
        if path.exists():
            return path
        return None
    
    cwd = Path.cwd()
    for name in [".gitsec.yml", "gitsec.yml", ".gitsec.yaml", "gitsec.yaml"]:
        path = cwd / name
        if path.exists():
            return path
    
    home = Path.home()
    for name in [".gitsec.yml", ".gitsec.yaml"]:
        path = home / name
        if path.exists():
            return path
    
    return None


def load_config_file(config_path: Path) -> Dict[str, Any]:
    if not config_path.exists():
        raise ValueError(f"Configuration file not found: {config_path}")
    
    content = config_path.read_text()
    suffix = config_path.suffix.lower()
    
    try:
        if suffix in [".yml", ".yaml"]:
            data = yaml.safe_load(content)
        elif suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported config file format: {suffix}. Use .yml, .yaml, or .json")
        
        return data or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in config file: {e}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file: {e}")


def load_config(config_path: Optional[str] = None) -> Optional[GitsecConfig]:
    discovered_path = discover_config_file(config_path)
    if not discovered_path:
        return None
    
    data = load_config_file(discovered_path)
    
    try:
        config = GitsecConfig(**data)
        return config
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}")


def merge_cli_args(
    config: Optional[GitsecConfig],
    cli_args: Dict[str, Any]
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    
    if not config:
        return cli_args
    
    if config.target:
        if config.target.org:
            result["org"] = config.target.org
        if config.target.repo:
            result["repo"] = config.target.repo
        if config.target.local_repo:
            result["local_repo"] = config.target.local_repo
    
    if config.base_url:
        result["base_url"] = config.base_url
    
    if config.output_folder:
        result["out_folder"] = config.output_folder
    
    if config.default_branch:
        result["branch"] = config.default_branch
    
    if config.repositories and config.repositories.max_count is not None:
        result["max_repos"] = config.repositories.max_count
    
    for key, value in cli_args.items():
        if value is not None:
            result[key] = value
    
    return result
