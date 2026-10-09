"""Fetch a submitted URL and turn the page into an Offer (FR-3).

The page is downloaded, never executed or rendered (NFR-5): scripts are dropped and
only the main text and links are kept.

A submitted URL is attacker-controlled, so every hop is checked before it is
requested: http/https on the default port only, no credentials in the URL, and the
host must resolve to public addresses only. The request is then sent to the
address that was checked (with the real Host header and TLS name), so a DNS answer
that changes between the check and the request cannot reach an internal address.
"""

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

import httpx
import trafilatura

from app.domain_intel import _ssl_context
from app.models import Offer
from app.parser import _html_to_text, extract_links

# NFR-1 allows 6 s for URL input; the detectors take up to 2.5 s after this.
FETCH_TIMEOUT_S = 3.0
MAX_REDIRECT_HOPS = 3
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_LINKS = 50
HTML_TYPES = ("text/html", "application/xhtml+xml")
DEFAULT_PORTS = {"http": 80, "https": 443}
USER_AGENT = "LegitInternshipDetector/0.1 (+offer check; page is not rendered)"

_HREF_RE = r"""href\s*=\s*["']([^"']+)["']"""

# Tests replace these so they never touch the network or real DNS.
TRANSPORT: httpx.AsyncBaseTransport | None = None
Resolver = Callable[[str, int], Awaitable[list[str]]]


class FetchError(ValueError):
    """The URL could not be fetched as an HTML page (API answers 422)."""


async def _system_resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


RESOLVE: Resolver = _system_resolve


def normalise_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise FetchError("URL is empty.")
    if "://" not in url:
        url = "https://" + url
    return url


def _parse(url: str) -> httpx.URL:
    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL as exc:
        raise FetchError("URL is not valid.") from exc
    if parsed.scheme not in DEFAULT_PORTS:
        raise FetchError("Only http and https URLs can be checked.")
    if parsed.userinfo:
        raise FetchError("URLs with a username or password are not fetched.")
    if parsed.port not in (None, DEFAULT_PORTS[parsed.scheme]):
        raise FetchError("Only the default http/https ports are fetched.")
    if not parsed.host:
        raise FetchError("URL has no host.")
    return parsed


async def _public_address(url: httpx.URL) -> str:
    """Resolve one hop's host and return the address to connect to."""
    host = url.raw_host.decode("ascii")  # IDNA-encoded
    try:
        addresses = await RESOLVE(host, DEFAULT_PORTS[url.scheme])
    except OSError as exc:
        raise FetchError(f"Could not resolve {url.host}.") from exc
    if not addresses:
        raise FetchError(f"Could not resolve {url.host}.")
    for addr in addresses:
        if not ipaddress.ip_address(addr.split("%", 1)[0]).is_global:
            raise FetchError("URL points to a private or reserved address.")
    return addresses[0]


def _pinned_request(client: httpx.AsyncClient, url: httpx.URL, addr: str) -> httpx.Request:
    """Request `url` from `addr`, keeping the real Host header and TLS server name."""
    host = url.raw_host.decode("ascii")
    return client.build_request(
        "GET",
        url.copy_with(host=addr),
        headers={"Host": host},
        extensions={"sni_hostname": host},
    )


async def _download(url: str) -> tuple[str, str]:
    """(final_url, html). Follows at most MAX_REDIRECT_HOPS redirects, checking each."""
    async with httpx.AsyncClient(
        transport=TRANSPORT,
        verify=_ssl_context(),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
    ) as client:
        current = url
        for _ in range(MAX_REDIRECT_HOPS + 1):
            parsed = _parse(current)
            addr = await _public_address(parsed)
            request = _pinned_request(client, parsed, addr)
            response = await client.send(request, stream=True)
            try:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise FetchError("Redirect without a destination.")
                    current = urljoin(current, location)
                    continue
                if response.status_code >= 400:
                    raise FetchError(f"Page returned HTTP {response.status_code}.")
                content_type = response.headers.get("content-type", "").lower()
                if not content_type.startswith(HTML_TYPES):
                    raise FetchError("URL is not an HTML page.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_PAGE_BYTES:
                        raise FetchError("Page is too large (max 2 MB).")
                return current, bytes(body).decode(response.encoding or "utf-8", "replace")
            finally:
                await response.aclose()
        raise FetchError("Too many redirects.")


def _page_links(html: str, base_url: str) -> list[str]:
    links: dict[str, None] = {}
    for href in re.findall(_HREF_RE, html, re.IGNORECASE):
        absolute = urljoin(base_url, href.strip())
        if absolute.lower().startswith(("http://", "https://")):
            links.setdefault(absolute.split("#", 1)[0], None)
        if len(links) >= MAX_LINKS:
            break
    return list(links)


def html_to_offer(html: str, page_url: str, submitted_url: str) -> Offer:
    text = trafilatura.extract(html, include_comments=False, include_tables=True)
    if not text:
        text = _html_to_text(html)
    title = trafilatura.extract_metadata(html)
    title_text = title.title.strip() if title and title.title else ""
    body = text.strip()
    if title_text and not body.startswith(title_text):
        body = f"{title_text}\n\n{body}" if body else title_text
    if not body:
        raise FetchError("Page has no readable text.")

    # The page's own address comes first so domain intel checks it.
    links = list(
        dict.fromkeys([submitted_url, page_url, *extract_links(body), *_page_links(html, page_url)])
    )
    return Offer(source_type="url", body_text=body, links=links)


async def fetch_offer(url: str) -> Offer:
    submitted = normalise_url(url)
    try:
        page_url, html = await asyncio.wait_for(_download(submitted), FETCH_TIMEOUT_S)
    except FetchError:
        raise
    except TimeoutError as exc:
        raise FetchError("Page took too long to respond.") from exc
    except httpx.HTTPError as exc:
        raise FetchError("Page could not be reached.") from exc
    return await asyncio.to_thread(html_to_offer, html, page_url, submitted)
