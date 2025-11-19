from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

WARN_THRESHOLD = 10
FAIL_THRESHOLD = 25


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    try:
        secrets_response = client.get(f"/orgs/{org}/actions/secrets")
        secrets = secrets_response.get("secrets", [])

        if not secrets:
            return

        for secret in secrets:
            secret_name = secret.get("name", "unknown")
            visibility = secret.get("visibility", "unknown")

            if visibility == "all":
                yield Finding(
                    check_id="org-secrets-scope",
                    resource=f"org/{org}",
                    evidence=f"Secret '{secret_name}' is available to all repositories",
                    notes="Secret has 'all' visibility setting",
                )

            elif visibility == "selected":
                try:
                    repos_response = client.get(
                        f"/orgs/{org}/actions/secrets/{secret_name}/repositories"
                    )
                    repo_count = repos_response.get("total_count", 0)

                    if repo_count > FAIL_THRESHOLD:
                        yield Finding(
                            check_id="org-secrets-scope",
                            resource=f"org/{org}",
                            evidence=f"Secret '{secret_name}' is accessible to {repo_count} repositories",
                            notes=f"Exceeds threshold of {FAIL_THRESHOLD} repositories",
                        )
                    elif repo_count > WARN_THRESHOLD:
                        yield Finding(
                            check_id="org-secrets-scope",
                            resource=f"org/{org}",
                            evidence=f"Secret '{secret_name}' is accessible to {repo_count} repositories",
                            notes=f"Exceeds warning threshold of {WARN_THRESHOLD} repositories",
                        )

                except Exception as e:
                    yield Finding(
                        check_id="org-secrets-scope",
                        resource=f"org/{org}",
                        evidence=f"Error checking secret '{secret_name}' repository access",
                        notes=format_api_error(e),
                        is_error=True,
                    )

            elif visibility == "private":
                pass

            else:
                yield Finding(
                    check_id="org-secrets-scope",
                    resource=f"org/{org}",
                    evidence=f"Secret '{secret_name}' has unknown visibility type: {visibility}",
                    notes="Unable to determine secret scope",
                )

    except Exception as e:
        yield Finding(
            check_id="org-secrets-scope",
            resource=f"org/{org}",
            evidence="Error retrieving organization secrets",
            notes=format_api_error(e),
            is_error=True,
        )
