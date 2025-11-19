from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding


def run(client: GitHubClient, repo: str, **_) -> Iterable[Finding]:
    owner, name = repo.split("/", 1)

    try:
        runners_response = client.get(f"/repos/{owner}/{name}/actions/runners")
        runners = runners_response.get("runners", [])

        if not runners:
            return

        runner_count = len(runners)
        online_runners = [r for r in runners if r.get("status") == "online"]
        offline_runners = [r for r in runners if r.get("status") == "offline"]

        if runner_count > 5:
            yield Finding(
                check_id="repo-runners-scope",
                resource=f"repo/{repo}",
                evidence=f"Repository has {runner_count} runners configured",
                notes=f"May indicate over-provisioning (online: {len(online_runners)}, offline: {len(offline_runners)})",
            )

    except Exception as e:
        yield Finding(
            check_id="repo-runners-scope",
            resource=f"repo/{repo}",
            evidence="Error retrieving repository runners",
            notes=format_api_error(e),
            is_error=True,
        )
