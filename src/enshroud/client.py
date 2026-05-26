"""Async GraphQL HTTP client."""
from __future__ import annotations

import json
from typing import Any

import httpx


class GraphQLClient:
    """Async GraphQL client wrapping httpx."""

    def __init__(
        self,
        endpoint: str,
        auth_header: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if auth_header:
            # auth_header format: "Header-Name: value"
            if ":" in auth_header:
                name, _, value = auth_header.partition(":")
                headers[name.strip()] = value.strip()
        self.headers = headers

    async def query(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a GraphQL query and return the parsed JSON response."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.endpoint,
                headers=self.headers,
                content=json.dumps(payload),
            )
            resp.raise_for_status()
            return resp.json()

    async def options(self, extra_headers: dict[str, str] | None = None) -> httpx.Response:
        """Send an OPTIONS request."""
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        # Remove Content-Type for OPTIONS
        headers.pop("Content-Type", None)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.options(self.endpoint, headers=headers)
            return resp

    async def get_with_origin(self, origin: str) -> httpx.Response:
        """Send a GET request with a custom Origin header."""
        headers = dict(self.headers)
        headers["Origin"] = origin
        headers.pop("Content-Type", None)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(self.endpoint, headers=headers)
            return resp

    async def post_raw(
        self,
        query: str,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send a raw POST and return the httpx Response (not parsed)."""
        payload = {"query": query}
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.endpoint,
                headers=headers,
                content=json.dumps(payload),
            )
            return resp
