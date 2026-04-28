// Local, intentionally vulnerable XSS lab for the basic cases discussed in the blog.
//
// Run:
//
//	go run xss_basic_lab.go -addr 127.0.0.1:8009
//
// Then open http://127.0.0.1:8009/
//
// This lab binds to localhost by default. Do not expose it to a public network.
package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
)

var (
	mu       sync.Mutex
	comments []string
	websites []string
)

func page(w http.ResponseWriter, title string, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>%s</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; line-height: 1.55; }
    code, pre { background: #f5f5f5; padding: .15rem .3rem; border-radius: .25rem; }
    section { border: 1px solid #ddd; border-radius: 12px; padding: 1rem; margin: 1rem 0; }
    input, textarea { width: 100%%; padding: .4rem; margin: .25rem 0 .75rem; }
  </style>
</head>
<body>%s</body>
</html>`, template.HTMLEscapeString(title), body)
}

func index(w http.ResponseWriter, r *http.Request) {
	page(w, "Basic XSS lab", `
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
</section>`)
}

func reflectedHTML(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	// Intentionally vulnerable: direct HTML insertion, no output encoding.
	page(w, "Reflected HTML", fmt.Sprintf(`<h1>Search results</h1><p>You searched for: %s</p><p><a href="/">Back</a></p>`, search))
}

func reflectedAttr(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	// Intentionally vulnerable: direct insertion into an HTML attribute.
	page(w, "Reflected attribute", fmt.Sprintf(`<h1>Search form</h1><p>Move the mouse over the input after injecting an event handler payload.</p><input name="search" value="%s"><p><a href="/">Back</a></p>`, search))
}

func postComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mu.Lock()
	comments = append(comments, r.Form.Get("comment")) // Intentionally vulnerable storage.
	mu.Unlock()
	http.Redirect(w, r, "/post", http.StatusSeeOther)
}

func viewPost(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	copyComments := append([]string(nil), comments...)
	mu.Unlock()
	var b strings.Builder
	if len(copyComments) == 0 {
		b.WriteString("<p>No comments yet.</p>")
	} else {
		for _, c := range copyComments {
			fmt.Fprintf(&b, "<article class='comment'>%s</article>\n", c)
		}
	}
	b.WriteString(`<form action="/comment" method="post"><textarea name="comment"></textarea><button>Post another comment</button></form><p><a href="/">Back</a></p>`)
	page(w, "Stored comments", "<h1>Stored comments</h1>"+b.String())
}

func postProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mu.Lock()
	websites = append(websites, r.Form.Get("website")) // Intentionally vulnerable storage into href later.
	mu.Unlock()
	http.Redirect(w, r, "/profiles", http.StatusSeeOther)
}

func viewProfiles(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	copyWebsites := append([]string(nil), websites...)
	mu.Unlock()
	var b strings.Builder
	b.WriteString(`<h1>Stored profile links</h1><p>Clicking a saved <code>javascript:</code> URL demonstrates the href-sink case.</p><ul>`)
	if len(copyWebsites) == 0 {
		b.WriteString("<li>No profiles yet.</li>")
	} else {
		for _, website := range copyWebsites {
			fmt.Fprintf(&b, `<li><a class="website" href="%s">personal site</a></li>`, website)
		}
	}
	b.WriteString(`</ul><form action="/profile" method="post"><input name="website"><button>Save another website</button></form><p><a href="/">Back</a></p>`)
	page(w, "Stored href profiles", b.String())
}

func domDocumentWrite(w http.ResponseWriter, r *http.Request) {
	page(w, "DOM document.write", `
<h1>DOM XSS: document.write</h1>
<script>
  const params = new URLSearchParams(location.search);
  const searchTerms = params.get('search') || '';
  // Intentionally vulnerable sink: user-controlled location.search reaches document.write.
  document.write('<img src="/resources/images/tracker.gif?searchTerms=' + searchTerms + '">');
</script>
<p><a href="/">Back</a></p>`)
}

func domInnerHTML(w http.ResponseWriter, r *http.Request) {
	page(w, "DOM innerHTML", `
<h1>DOM XSS: innerHTML</h1>
<div id="searchMessage"></div>
<script>
  const params = new URLSearchParams(location.search);
  const message = params.get('search') || '';
  // Intentionally vulnerable sink: user-controlled location.search reaches innerHTML.
  document.getElementById('searchMessage').innerHTML = message;
</script>
<p><a href="/">Back</a></p>`)
}

func domHref(w http.ResponseWriter, r *http.Request) {
	page(w, "DOM href", `
<h1>DOM XSS: href sink</h1>
<p><a id="backLink" href="/">Back</a></p>
<script>
  const params = new URLSearchParams(location.search);
  const returnPath = params.get('returnPath') || '/';
  // Intentionally vulnerable sink: user-controlled location.search reaches an anchor href.
  document.getElementById('backLink').href = returnPath;
</script>`)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8009", "listen address; keep localhost unless you know what you are doing")
	flag.Parse()
	if !strings.HasPrefix(*addr, "127.0.0.1:") && !strings.HasPrefix(*addr, "localhost:") {
		log.Printf("WARNING: this app is intentionally vulnerable. Prefer 127.0.0.1.")
	}

	http.HandleFunc("/", index)
	http.HandleFunc("/reflected-html", reflectedHTML)
	http.HandleFunc("/reflected-attr", reflectedAttr)
	http.HandleFunc("/comment", postComment)
	http.HandleFunc("/post", viewPost)
	http.HandleFunc("/profile", postProfile)
	http.HandleFunc("/profiles", viewProfiles)
	http.HandleFunc("/dom-document-write", domDocumentWrite)
	http.HandleFunc("/dom-innerhtml", domInnerHTML)
	http.HandleFunc("/dom-href", domHref)

	log.Printf("Serving intentionally vulnerable lab at http://%s/", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
