from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import httpx


class GitHubAPIError(Exception):
    pass


def format_api_error(error: Exception, context: str = "") -> str:
    error_str = str(error)

    if "404" in error_str or "Not Found" in error_str:
        return f"{error_str}. Likely causes: resource doesn't exist, insufficient token permissions (needs 'repo' scope for private repos, 'admin:org' for org settings), or token expired."
    elif "403" in error_str or "Forbidden" in error_str:
        return f"{error_str}. Likely cause: insufficient token permissions. Required scopes may include 'repo', 'admin:org', 'read:org', or specific resource permissions."
    elif "401" in error_str or "Unauthorized" in error_str:
        return f"{error_str}. Likely cause: invalid or expired token."
    elif "rate limit" in error_str.lower():
        return f"{error_str}. API rate limit exceeded. Wait before retrying or use a token with higher rate limits."
    else:
        return f"{error_str}. Check token permissions and resource accessibility."


class GitHubClient:
    def __init__(
        self,
        token: str,
        base_url: str = "https://api.github.com",
        *,
        timeout: float = 15.0,
        api_version: str = "2022-11-28",
        user_agent: str = "git-sec-posture-mgmt/0.1",
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not token:
            raise ValueError("GitHub token is required.")
        if not base_url.startswith("http"):
            raise ValueError("Invalid base URL (must start with http/https).")

        self.input_base = base_url.rstrip("/")
        self.api_base, self.graphql_url = self._normalize_bases(self.input_base)
        self._rate_limit_notified = False
        self._progress_callback = progress_callback

        self.client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": api_version,
                "User-Agent": user_agent,
            },
            timeout=timeout,
            follow_redirects=True,
        )

    def _check_rate_limit(self, response: httpx.Response) -> None:
        remaining = response.headers.get("x-ratelimit-remaining")
        reset_time = response.headers.get("x-ratelimit-reset")

        if remaining and reset_time:
            remaining_int = int(remaining)

            if remaining_int <= 10 and remaining_int > 0:
                if not self._rate_limit_notified:
                    if self._progress_callback:
                        self._progress_callback(
                            f"Rate limit low: {remaining_int} remaining"
                        )
                    else:
                        print(
                            f"[WARNING] Rate limit low ({remaining_int} requests remaining). Continuing carefully..."
                        )
                    self._rate_limit_notified = True

            if remaining_int == 0:
                reset_timestamp = int(reset_time)
                wait_seconds = reset_timestamp - int(time.time())

                if wait_seconds > 0:
                    reset_dt = datetime.fromtimestamp(reset_timestamp)
                    if self._progress_callback:
                        self._progress_callback(
                            f"Rate limit reached, waiting {wait_seconds}s..."
                        )
                    else:
                        print(
                            f"[WAIT] Rate limit reached. Waiting until {reset_dt.strftime('%H:%M:%S')} ({wait_seconds}s)..."
                        )
                    time.sleep(wait_seconds + 2)
                    if self._progress_callback:
                        self._progress_callback("Resumed after rate limit")
                    else:
                        print("[OK] Resuming operations")
                    self._rate_limit_notified = False

    def get(self, endpoint: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("GET", endpoint, params=params)

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = (
            f"{self.api_base}{endpoint}"
            if endpoint.startswith("/")
            else f"{self.api_base}/{endpoint}"
        )
        resp = self.client.request(method, url, params=params, json=json)

        if resp.status_code >= 500:
            resp = self.client.request(method, url, params=params, json=json)

        self._check_rate_limit(resp)

        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            msg = None
            try:
                msg = resp.json().get("message")
            except Exception:
                pass
            raise GitHubAPIError(msg or str(e)) from e

        return resp.json() if resp.content else None

    def rest_paginate(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        per_page: int = 100,
        max_pages: Optional[int] = None,
    ) -> List[Any]:
        url = (
            f"{self.api_base}{endpoint}"
            if endpoint.startswith("/")
            else f"{self.api_base}/{endpoint}"
        )
        params = dict(params or {})
        params.setdefault("per_page", per_page)

        out: List[Any] = []
        pages = 0

        while url:
            resp = self.client.get(url, params=params)

            self._check_rate_limit(resp)

            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise GitHubAPIError(str(e)) from e

            data = resp.json()
            if isinstance(data, list):
                out.extend(data)
            else:
                items = data.get("items")
                if isinstance(items, list):
                    out.extend(items)
                else:
                    out.append(data)

            pages += 1
            if max_pages and pages >= max_pages:
                break

            url = resp.links.get("next", {}).get("url") or ""
            params = None

        return out

    def graphql(
        self, *, query: str, variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        resp = self.client.post(
            self.graphql_url, json={"query": query, "variables": variables or {}}
        )

        self._check_rate_limit(resp)

        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise GitHubAPIError(str(e)) from e

        data = resp.json()
        errors = data.get("errors")
        if errors:
            raise GitHubAPIError(errors[0].get("message", "GraphQL error"))
        return data

    @staticmethod
    def _normalize_bases(input_base: str) -> tuple[str, str]:
        b = input_base.rstrip("/")
        if "api.github.com" in b:
            api_base = "https://api.github.com"
            graphql = f"{api_base}/graphql"
            return api_base, graphql
        root = b
        if root.endswith("/api/v3"):
            root = root[:-6]
        if root.endswith("/api"):
            root = root[:-4]
        api_base = f"{root}/api/v3"
        graphql = f"{root}/api/graphql"
        return api_base, graphql

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
