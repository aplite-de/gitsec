from typing import Iterable, Optional

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

_QUERY = """
query($org: String!, $after: String) {
  organization(login: $org) {
    repositories(first: 100, after: $after, orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        nameWithOwner
        owner { login }
        name
      }
    }
  }
}
"""


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    after: Optional[str] = None

    while True:
        payload = client.graphql(query=_QUERY, variables={"org": org, "after": after})
        repos = (
            (payload.get("data") or {}).get("organization", {}).get("repositories", {})
        )

        for node in repos.get("nodes") or []:
            entity = node.get("nameWithOwner")
            owner = node.get("owner", {}).get("login")
            name = node.get("name")

            if not owner or not name:
                continue

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

                if not has_tag_protection:
                    if rulesets_response:
                        yield Finding(
                            check_id="org-tag-deletion-protection",
                            resource=f"repo/{entity}",
                            evidence=f"Repository '{entity}' does not have tag deletion protection enabled",
                        )
                    else:
                        yield Finding(
                            check_id="org-tag-deletion-protection",
                            resource=f"repo/{entity}",
                            evidence=f"Repository '{entity}' has no rulesets configured",
                            notes="No repository rulesets configured for tag protection",
                        )

            except Exception as e:
                if "404" in str(e):
                    yield Finding(
                        check_id="org-tag-deletion-protection",
                        resource=f"repo/{entity}",
                        evidence="Repository rulesets API not available",
                        notes="May require GitHub Enterprise or specific permissions",
                        is_error=True,
                    )
                else:
                    yield Finding(
                        check_id="org-tag-deletion-protection",
                        resource=f"repo/{entity}",
                        evidence="Error checking tag deletion protection",
                        notes=format_api_error(e),
                        is_error=True,
                    )

        pi = repos.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        after = pi.get("endCursor")
