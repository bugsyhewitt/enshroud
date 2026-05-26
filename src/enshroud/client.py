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

    async def post_form(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Send a query as application/x-www-form-urlencoded POST.

        Browsers can issue this content type without a CORS preflight, so a
        server that accepts mutations here is exposed to cross-site request
        forgery. Returns the raw httpx Response.
        """
        headers = dict(self.headers)
        # Override the JSON content type; httpx sets the form one from `data`.
        headers.pop("Content-Type", None)
        data: dict[str, str] = {"query": query}
        if variables:
            data["variables"] = json.dumps(variables)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.endpoint,
                headers=headers,
                data=data,
            )
            return resp

    async def get_query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Send a query via GET with the query string in the URL.

        GET requests are simple requests that bypass CORS preflight entirely.
        A server that executes mutations over GET is exposed to CSRF via
        `<img>` / `<script>` / link prefetch. Returns the raw httpx Response.
        """
        headers = dict(self.headers)
        headers.pop("Content-Type", None)
        params: dict[str, str] = {"query": query}
        if variables:
            params["variables"] = json.dumps(variables)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                self.endpoint,
                headers=headers,
                params=params,
            )
            return resp
