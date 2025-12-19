from typing import Iterable, Optional

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding


def run(client: GitHubClient, repo: str, branch: Optional[str] = None, **_) -> Iterable[Finding]:
    owner, name = repo.split("/", 1)

    try:
        rulesets_response = client.get(f"/repos/{owner}/{name}/rulesets")

        has_tag_protection = False
        protection_details = []

        for ruleset in rulesets_response:
            if ruleset.get("enforcement") == "active":
                rules = ruleset.get("rules", [])
                for rule in rules:
                    if (
                        rule.get("type") == "deletion"
                        and "tag" in str(ruleset.get("conditions", {})).lower()
                    ):
                        has_tag_protection = True
                        protection_details.append(
                            f"ruleset={ruleset.get('name', 'unnamed')}"
                        )
                        break

        if has_tag_protection:
            pass
        else:
            if rulesets_response:
                yield Finding(
                    check_id="repo-tag-deletion-protection",
                    resource=f"repo/{repo}",
                    evidence="Tag deletion protection is not enabled",
                    notes="Repository has rulesets but no active tag deletion protection",
                )
            else:
                yield Finding(
                    check_id="repo-tag-deletion-protection",
                    resource=f"repo/{repo}",
                    evidence="Tag deletion protection is not enabled",
                    notes="No repository rulesets configured",
                )

    except Exception as e:
        if "404" in str(e):
            yield Finding(
                check_id="repo-tag-deletion-protection",
                resource=f"repo/{repo}",
                evidence="Cannot determine tag deletion protection status",
                notes="Repository rulesets API not available (may require GitHub Enterprise or specific permissions)",
                is_error=True,
            )
        else:
            yield Finding(
                check_id="repo-tag-deletion-protection",
                resource=f"repo/{repo}",
                evidence="Error checking tag deletion protection",
                notes=format_api_error(e),
                is_error=True,
            )
