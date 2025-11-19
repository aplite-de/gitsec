from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    try:
        data = client.get(f"/orgs/{org}")
        mfa_enabled = data.get("two_factor_requirement_enabled", None)

        if mfa_enabled is False:
            yield Finding(
                check_id="org-mfa",
                resource=f"org/{org}",
                evidence="Organization does not require two-factor authentication for members",
            )
        elif mfa_enabled is None:
            yield Finding(
                check_id="org-mfa",
                resource=f"org/{org}",
                evidence="Unable to determine MFA status",
                notes="Field not visible with this token or GHES version may not support this check",
                is_error=True,
            )

    except Exception as e:
        yield Finding(
            check_id="org-mfa",
            resource=f"org/{org}",
            evidence="Error checking MFA status",
            notes=format_api_error(e),
            is_error=True,
        )
