from dataclasses import dataclass
from typing import Callable

from ..modules.checks.org.mfa_required import run as mfa_run
from ..modules.checks.org.repo_commit_signing_required import (
    run as org_commit_signing_run,
)
from ..modules.checks.org.repo_pr_required import run as org_pr_required_run
from ..modules.checks.org.repo_push_protection import run as org_push_protection_run
from ..modules.checks.org.repo_tag_deletion_protection import (
    run as org_tag_deletion_protection_run,
)
from ..modules.checks.org.runners_scope import run as org_runners_scope_run
from ..modules.checks.org.secrets_scope import run as org_secrets_scope_run
from ..modules.checks.org.sso_enabled import run as sso_run
from ..modules.checks.org.user_access import run as org_user_access_run
from ..modules.checks.repo.commit_signing_required import run as repo_commit_signing_run
from ..modules.checks.repo.pr_required import run as repo_pr_required_run
from ..modules.checks.repo.push_protection import run as repo_push_protection_run
from ..modules.checks.repo.runners_scope import run as repo_runners_scope_run
from ..modules.checks.repo.tag_deletion_protection import (
    run as repo_tag_deletion_protection_run,
)


@dataclass
class ModuleConfig:
    name: str
    description: str
    run_func: Callable
    output_file: str
    scope: str  # "org", "repo", or "both"
    requires_max_repos: bool = False


MODULES = {
    "org-mfa": ModuleConfig(
        name="org-mfa",
        description="Check if organization requires MFA for members",
        run_func=mfa_run,
        output_file="org_mfa_required.csv",
        scope="org",
    ),
    "org-sso": ModuleConfig(
        name="org-sso",
        description="Check if organization has SSO/SAML enabled",
        run_func=sso_run,
        output_file="org_sso_enabled.csv",
        scope="org",
    ),
    "org-commit-signing": ModuleConfig(
        name="org-commit-signing",
        description="Check commit signing requirements across all org repositories",
        run_func=org_commit_signing_run,
        output_file="org_commit_signing_required.csv",
        scope="org",
    ),
    "org-pr-required": ModuleConfig(
        name="org-pr-required",
        description="Check PR requirements on default branch across all org repositories",
        run_func=org_pr_required_run,
        output_file="org_pr_required.csv",
        scope="org",
    ),
    "org-push-protection": ModuleConfig(
        name="org-push-protection",
        description="Check push protection on default branch across all org repositories",
        run_func=org_push_protection_run,
        output_file="org_push_protection.csv",
        scope="org",
    ),
    "org-tag-deletion-protection": ModuleConfig(
        name="org-tag-deletion-protection",
        description="Check tag deletion protection across all org repositories",
        run_func=org_tag_deletion_protection_run,
        output_file="org_tag_deletion_protection.csv",
        scope="org",
    ),
    "org-secrets-scope": ModuleConfig(
        name="org-secrets-scope",
        description="Audit organization-level Actions secrets scope",
        run_func=org_secrets_scope_run,
        output_file="org_secrets_scope.csv",
        scope="org",
    ),
    "org-runners-scope": ModuleConfig(
        name="org-runners-scope",
        description="Audit organization-level Actions runners scope",
        run_func=org_runners_scope_run,
        output_file="org_runners_scope.csv",
        scope="org",
    ),
    "org-user-access": ModuleConfig(
        name="org-user-access",
        description="Analyze user access patterns across organization repositories",
        run_func=org_user_access_run,
        output_file="org_user_access.csv",
        scope="org",
        requires_max_repos=True,
    ),
    "repo-commit-signing": ModuleConfig(
        name="repo-commit-signing",
        description="Check commit signing requirements for a repository",
        run_func=repo_commit_signing_run,
        output_file="repo_commit_signing_required.csv",
        scope="repo",
    ),
    "repo-pr-required": ModuleConfig(
        name="repo-pr-required",
        description="Check PR requirements on default branch for a repository",
        run_func=repo_pr_required_run,
        output_file="repo_pr_required.csv",
        scope="repo",
    ),
    "repo-push-protection": ModuleConfig(
        name="repo-push-protection",
        description="Check push protection on default branch for a repository",
        run_func=repo_push_protection_run,
        output_file="repo_push_protection.csv",
        scope="repo",
    ),
    "repo-tag-deletion-protection": ModuleConfig(
        name="repo-tag-deletion-protection",
        description="Check tag deletion protection for a repository",
        run_func=repo_tag_deletion_protection_run,
        output_file="repo_tag_deletion_protection.csv",
        scope="repo",
    ),
    "repo-runners-scope": ModuleConfig(
        name="repo-runners-scope",
        description="Audit repository-level Actions runners scope",
        run_func=repo_runners_scope_run,
        output_file="repo_runners_scope.csv",
        scope="repo",
    ),
}
