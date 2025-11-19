from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

WARN_THRESHOLD = 10
FAIL_THRESHOLD = 25


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    try:
        runner_groups_response = client.get(f"/orgs/{org}/actions/runner-groups")
        runner_groups = runner_groups_response.get("runner_groups", [])

        if not runner_groups:
            return

        for group in runner_groups:
            group_id = group.get("id")
            group_name = group.get("name", "unknown")
            visibility = group.get("visibility", "unknown")

            if visibility == "all":
                yield Finding(
                    check_id="org-runners-scope",
                    resource=f"org/{org}",
                    evidence=f"Runner group '{group_name}' is available to all repositories",
                    notes="Runner group has 'all' visibility setting",
                )

            elif visibility == "selected":
                try:
                    repos_response = client.get(
                        f"/orgs/{org}/actions/runner-groups/{group_id}/repositories"
                    )
                    repo_count = repos_response.get("total_count", 0)

                    if repo_count > FAIL_THRESHOLD:
                        yield Finding(
                            check_id="org-runners-scope",
                            resource=f"org/{org}",
                            evidence=f"Runner group '{group_name}' is accessible to {repo_count} repositories",
                            notes=f"Exceeds threshold of {FAIL_THRESHOLD} repositories",
                        )
                    elif repo_count > WARN_THRESHOLD:
                        yield Finding(
                            check_id="org-runners-scope",
                            resource=f"org/{org}",
                            evidence=f"Runner group '{group_name}' is accessible to {repo_count} repositories",
                            notes=f"Exceeds warning threshold of {WARN_THRESHOLD} repositories",
                        )

                except Exception as e:
                    yield Finding(
                        check_id="org-runners-scope",
                        resource=f"org/{org}",
                        evidence=f"Error checking runner group '{group_name}' repository access",
                        notes=format_api_error(e),
                        is_error=True,
                    )

            elif visibility == "private":
                pass

            else:
                yield Finding(
                    check_id="org-runners-scope",
                    resource=f"org/{org}",
                    evidence=f"Runner group '{group_name}' has unknown visibility type: {visibility}",
                    notes="Unable to determine runner group scope",
                )

        try:
            client.get(f"/orgs/{org}/actions/runners")
        except Exception:
            pass

    except Exception as e:
        yield Finding(
            check_id="org-runners-scope",
            resource=f"org/{org}",
            evidence="Error retrieving organization runner groups",
            notes=format_api_error(e),
            is_error=True,
        )
