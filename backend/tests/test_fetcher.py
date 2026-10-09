import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app import fetcher
from app.fetcher import FetchError, fetch_offer
from app.main import app

PUBLIC_IP = "93.184.216.34"

SCAM_PAGE = """<html><head><title>Amazon WFH Internship</title>
<script>alert("never run")</script></head><body>
<article><h1>Amazon WFH Internship</h1>
<p>Congratulations! You are selected for Work From Home data entry job at Amazon.
Pay Rs 1999 registration fee within 24 hours to confirm your seat.</p>
<p>Contact amazon.hr.jobs@gmail.com or WhatsApp 98765 43210.</p>
<a href="/apply">Apply</a> <a href="https://bit.ly/abc">Pay now</a>
</article></body></html>"""


def use_dns(monkeypatch, table: dict[str, list[str]]):
    async def resolve(host: str, port: int) -> list[str]:
        if host not in table:
            raise OSError("no such host")
        return table[host]

    monkeypatch.setattr(fetcher, "RESOLVE", resolve)


def use_server(monkeypatch, handler):
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(fetcher, "TRANSPORT", httpx.MockTransport(record))
    return seen


def html(body: str, status: int = 200) -> httpx.Response:
    return httpx.Response(status, text=body, headers={"content-type": "text/html; charset=utf-8"})


def run(url: str):
    return asyncio.run(fetch_offer(url))


def test_fetches_page_text_and_links(monkeypatch):
    use_dns(monkeypatch, {"jobs.example.com": [PUBLIC_IP]})
    seen = use_server(monkeypatch, lambda r: html(SCAM_PAGE))

    offer = run("jobs.example.com/offer")

    assert offer.source_type == "url"
    assert "registration fee" in offer.body_text
    assert "never run" not in offer.body_text
    assert offer.links[0] == "https://jobs.example.com/offer"
    assert "https://jobs.example.com/apply" in offer.links
    assert "https://bit.ly/abc" in offer.links
    # Sent to the checked address with the real host name.
    assert seen[0].url.host == PUBLIC_IP
    assert seen[0].headers["host"] == "jobs.example.com"
    assert seen[0].extensions["sni_hostname"] == "jobs.example.com"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/x",
        "https://user:pw@example.com/",
        "https://example.com:8443/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_rejects_unsafe_urls(monkeypatch, url):
    use_dns(
        monkeypatch,
        {
            "example.com": [PUBLIC_IP],
            "localhost": ["127.0.0.1"],
            "169.254.169.254": ["169.254.169.254"],
        },
    )
    seen = use_server(monkeypatch, lambda r: html(SCAM_PAGE))
    with pytest.raises(FetchError):
        run(url)
    assert seen == []


def test_rejects_host_with_any_private_address(monkeypatch):
    use_dns(monkeypatch, {"mixed.example": [PUBLIC_IP, "10.0.0.5"]})
    seen = use_server(monkeypatch, lambda r: html(SCAM_PAGE))
    with pytest.raises(FetchError, match="private"):
        run("https://mixed.example/")
    assert seen == []


def test_redirect_to_internal_host_is_blocked(monkeypatch):
    use_dns(monkeypatch, {"short.example": [PUBLIC_IP], "internal.corp": ["192.168.1.10"]})

    def server(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://internal.corp/admin"})

    seen = use_server(monkeypatch, server)
    with pytest.raises(FetchError, match="private"):
        run("https://short.example/x")
    assert len(seen) == 1


def test_follows_public_redirect(monkeypatch):
    use_dns(monkeypatch, {"short.example": [PUBLIC_IP], "jobs.example.com": [PUBLIC_IP]})

    def server(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "short.example":
            return httpx.Response(301, headers={"location": "https://jobs.example.com/offer"})
        return html(SCAM_PAGE)

    use_server(monkeypatch, server)
    offer = run("https://short.example/x")
    assert offer.links[:2] == ["https://short.example/x", "https://jobs.example.com/offer"]


def test_too_many_redirects(monkeypatch):
    use_dns(monkeypatch, {"loop.example": [PUBLIC_IP]})
    use_server(monkeypatch, lambda r: httpx.Response(302, headers={"location": "/again"}))
    with pytest.raises(FetchError, match="redirects"):
        run("https://loop.example/")


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(404, text="nope", headers={"content-type": "text/html"}), "404"),
        (httpx.Response(200, content=b"%PDF", headers={"content-type": "application/pdf"}), "HTML"),
        (html("<html><body><script>x()</script></body></html>"), "readable"),
    ],
)
def test_unusable_pages(monkeypatch, response, message):
    use_dns(monkeypatch, {"example.com": [PUBLIC_IP]})
    use_server(monkeypatch, lambda r: response)
    with pytest.raises(FetchError, match=message):
        run("https://example.com/")


def test_page_too_large(monkeypatch):
    use_dns(monkeypatch, {"example.com": [PUBLIC_IP]})
    big = "<html><body>" + "a" * (fetcher.MAX_PAGE_BYTES + 10) + "</body></html>"
    use_server(monkeypatch, lambda r: html(big))
    with pytest.raises(FetchError, match="too large"):
        run("https://example.com/")


def test_network_error_becomes_fetch_error(monkeypatch):
    use_dns(monkeypatch, {"example.com": [PUBLIC_IP]})

    def server(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    use_server(monkeypatch, server)
    with pytest.raises(FetchError, match="reached"):
        run("https://example.com/")


def test_analyze_url_endpoint(monkeypatch):
    use_dns(monkeypatch, {"jobs.example.com": [PUBLIC_IP]})
    use_server(monkeypatch, lambda r: html(SCAM_PAGE))
    r = TestClient(app).post("/api/v1/analyze", json={"url": "https://jobs.example.com/offer"})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["red_flags"]}
    assert {"R-FEE", "C-IMPERSONATION"} <= ids
    assert r.json()["detectors"]["headers"]["status"] == "skipped"


def test_analyze_url_unreachable_is_422(monkeypatch):
    r = TestClient(app).post("/api/v1/analyze", json={"url": "https://nowhere.invalid/"})
    assert r.status_code == 422
