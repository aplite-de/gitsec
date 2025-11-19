from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

_QUERY = """
query($org: String!) {
  organization(login: $org) {
    samlIdentityProvider { id ssoUrl }
  }
}
"""


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    try:
        payload = client.graphql(query=_QUERY, variables={"org": org})
        org_data = (payload or {}).get("data", {}).get("organization")
        sso_provider = (
            org_data.get("samlIdentityProvider") if isinstance(org_data, dict) else None
        )

        if not sso_provider:
            yield Finding(
                check_id="org-sso",
                resource=f"org/{org}",
                evidence="Organization does not have SAML SSO configured",
            )
    except Exception as e:
        yield Finding(
            check_id="org-sso",
            resource=f"org/{org}",
            evidence="Error checking SSO status",
            notes=format_api_error(e),
            is_error=True,
        )
