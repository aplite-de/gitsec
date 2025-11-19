from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

import httpx


@dataclass
class Advisory:

    id: str
    url: str
    title: str
    aliases: list[str]
    cvss3_score: Optional[float] = None
    cvss3_vector: Optional[str] = None


@dataclass
class PackageVersion:

    system: str
    name: str
    version: str
    published_at: str
    is_deprecated: bool
    licenses: list[str]
    advisory_ids: list[str]


class DepsDevClient:
    BASE_URL = "https://api.deps.dev/v3alpha"

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def get_version_info(
        self, ecosystem: str, package_name: str, version: str
    ) -> Optional[PackageVersion]:
        encoded_name = quote(package_name, safe="")
        encoded_version = quote(version, safe="")
        url = f"{self.BASE_URL}/systems/{ecosystem}/packages/{encoded_name}/versions/{encoded_version}"

        try:
            response = self._client.get(url)
            if response.status_code != 200:
                return None

            data = response.json()
            return PackageVersion(
                system=ecosystem,
                name=package_name,
                version=version,
                published_at=data.get("publishedAt", ""),
                is_deprecated=data.get("isDeprecated", False),
                licenses=data.get("licenses", []),
                advisory_ids=[adv.get("id") for adv in data.get("advisoryKeys", [])],
            )
        except Exception:
            return None

    def get_advisory(self, advisory_id: str) -> Optional[Advisory]:
        url = f"{self.BASE_URL}/advisories/{advisory_id}"

        try:
            response = self._client.get(url)
            if response.status_code != 200:
                return None

            data = response.json()
            return Advisory(
                id=advisory_id,
                url=data.get("url", ""),
                title=data.get("title", ""),
                aliases=data.get("aliases", []),
                cvss3_score=data.get("cvss3Score"),
                cvss3_vector=data.get("cvss3Vector"),
            )
        except Exception:
            return None

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
