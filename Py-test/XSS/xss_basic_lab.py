#!/usr/bin/env python3
"""
Local, intentionally vulnerable XSS lab for the basic cases discussed in the blog.

Run:
  python3 xss_basic_lab.py --host 127.0.0.1 --port 8008
Then open http://127.0.0.1:8008/

This lab binds to localhost by default. Do not expose it to a public network.
"""
from __future__ import annotations

import argparse
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List

COMMENTS: List[str] = []
WEBSITES: List[str] = []


def parse_form(body: bytes) -> Dict[str, str]:
    parsed = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {k: v[-1] if v else "" for k, v in parsed.items()}


def page(title: str, body: str) -> bytes:
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; line-height: 1.55; }}
    code, pre {{ background: #f5f5f5; padding: .15rem .3rem; border-radius: .25rem; }}
    section {{ border: 1px solid #ddd; border-radius: 12px; padding: 1rem; margin: 1rem 0; }}
    input, textarea {{ width: 100%; padding: .4rem; margin: .25rem 0 .75rem; }}
  </style>
</head>
<body>
{body}
</body>
</html>"""
    return html.encode("utf-8")


class XSSLabHandler(BaseHTTPRequestHandler):
    server_version = "BasicXSSLab/1.0"

    def send_html(self, title: str, body: str, status: int = 200) -> None:
        data = page(title, body)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib API name
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path

        if path == "/":
            self.send_html("Basic XSS lab", """
<h1>Basic XSS lab, localhost only</h1>
<p>These pages are intentionally vulnerable and are meant for local/authorized testing only.</p>
<section>
  <h2>1. Reflected XSS into HTML context</h2>
  <form action="/reflected-html" method="get"><input name="search" placeholder="try: &lt;script&gt;alert(1)&lt;/script&gt;"><button>Search</button></form>
</section>
<section>
  <h2>2. Reflected XSS into an attribute</h2>
  <form action="/reflected-attr" method="get"><input name="search" placeholder='try: &quot; onmouseover=&quot;alert(1)'><button>Search</button></form>
</section>
<section>
  <h2>3. Stored XSS into HTML context</h2>
  <form action="/comment" method="post"><textarea name="comment" placeholder="try: &lt;script&gt;alert(1)&lt;/script&gt;"></textarea><button>Post comment</button></form>
  <p><a href="/post">View stored comments</a></p>
</section>
<section>
  <h2>4. Stored XSS into href attribute</h2>
  <form action="/profile" method="post"><input name="website" placeholder="try: javascript:alert(1)"><button>Save website</button></form>
  <p><a href="/profiles">View profiles</a></p>
</section>
<section>
  <h2>5. DOM XSS: document.write sink using location.search</h2>
  <p><a href='/dom-document-write?search=%22%3E%3Csvg%20onload%3Dalert%281%29%3E'>Open demo</a></p>
</section>
<section>
  <h2>6. DOM XSS: innerHTML sink using location.search</h2>
  <p><a href='/dom-innerhtml?search=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E'>Open demo</a></p>
</section>
<section>
  <h2>7. DOM XSS: anchor href sink using returnPath</h2>
  <p><a href='/dom-href?returnPath=javascript%3Aalert%281%29'>Open demo, then click Back</a></p>
</section>
""")
            return

        if path == "/reflected-html":
            search = query.get("search", [""])[-1]
            # Intentionally vulnerable: direct HTML insertion, no output encoding.
            self.send_html("Reflected HTML", f"""
<h1>Search results</h1>
<p>You searched for: {search}</p>
<p><a href="/">Back</a></p>
""")
            return

        if path == "/reflected-attr":
            search = query.get("search", [""])[-1]
            # Intentionally vulnerable: direct insertion into an HTML attribute.
            self.send_html("Reflected attribute", f"""
<h1>Search form</h1>
<p>Move the mouse over the input after injecting an event handler payload.</p>
<input name="search" value="{search}">
<p><a href="/">Back</a></p>
""")
            return

        if path == "/post":
            rendered = "\n".join(f"<article class='comment'>{c}</article>" for c in COMMENTS) or "<p>No comments yet.</p>"
            self.send_html("Stored comments", f"""
<h1>Stored comments</h1>
{rendered}
<form action="/comment" method="post"><textarea name="comment"></textarea><button>Post another comment</button></form>
<p><a href="/">Back</a></p>
""")
            return

        if path == "/profiles":
            rendered = "\n".join(f"<li><a class='website' href=\"{w}\">personal site</a></li>" for w in WEBSITES) or "<li>No profiles yet.</li>"
            self.send_html("Stored href profiles", f"""
<h1>Stored profile links</h1>
<p>Clicking a saved <code>javascript:</code> URL demonstrates the href-sink case.</p>
<ul>{rendered}</ul>
<form action="/profile" method="post"><input name="website"><button>Save another website</button></form>
<p><a href="/">Back</a></p>
""")
            return

        if path == "/dom-document-write":
            self.send_html("DOM document.write", """
<h1>DOM XSS: document.write</h1>
<script>
  const params = new URLSearchParams(location.search);
  const searchTerms = params.get('search') || '';
  // Intentionally vulnerable sink: user-controlled location.search reaches document.write.
  document.write('<img src="/resources/images/tracker.gif?searchTerms=' + searchTerms + '">');
</script>
<p><a href="/">Back</a></p>
""")
            return

        if path == "/dom-innerhtml":
            self.send_html("DOM innerHTML", """
<h1>DOM XSS: innerHTML</h1>
<div id="searchMessage"></div>
<script>
  const params = new URLSearchParams(location.search);
  const message = params.get('search') || '';
  // Intentionally vulnerable sink: user-controlled location.search reaches innerHTML.
  document.getElementById('searchMessage').innerHTML = message;
</script>
<p><a href="/">Back</a></p>
""")
            return

        if path == "/dom-href":
            self.send_html("DOM href", """
<h1>DOM XSS: href sink</h1>
<p><a id="backLink" href="/">Back</a></p>
<script>
  const params = new URLSearchParams(location.search);
  const returnPath = params.get('returnPath') || '/';
  // Intentionally vulnerable sink: user-controlled location.search reaches an anchor href.
  document.getElementById('backLink').href = returnPath;
</script>
""")
            return

        self.send_html("Not found", "<h1>404</h1>", status=404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib API name
        length = int(self.headers.get("Content-Length", "0"))
        data = parse_form(self.rfile.read(length))
        if self.path == "/comment":
            # Intentionally vulnerable storage.
            COMMENTS.append(data.get("comment", ""))
            self.redirect("/post")
            return
        if self.path == "/profile":
            # Intentionally vulnerable storage into href later.
            WEBSITES.append(data.get("website", ""))
            self.redirect("/profiles")
            return
        self.send_html("Not found", "<h1>404</h1>", status=404)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local intentionally vulnerable XSS lab.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host. Keep 127.0.0.1 unless you know what you are doing.")
    parser.add_argument("--port", type=int, default=8008, help="Bind port.")
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("WARNING: this app is intentionally vulnerable. Prefer --host 127.0.0.1.", file=sys.stderr)

    server = ThreadingHTTPServer((args.host, args.port), XSSLabHandler)
    print(f"Serving intentionally vulnerable lab at http://{args.host}:{args.port}/")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
