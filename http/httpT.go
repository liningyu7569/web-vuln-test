package http

import (
	"fmt"
	"io"
	"net/http"
)

func HttpT() {
	fmt.Println("Go HTTP Client fetching data")

	resp, err := http.Get("http://127.0.0.1:8081")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	fmt.Println("Received : " + string(body))
	fmt.Println()
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "MY_Password_123")
}

func HttpS() {
	http.HandleFunc("/", handler)
	fmt.Println("Go HTTPS SERVER running on https://127.0.0.1:8082")

	err := http.ListenAndServeTLS("127.0.0.1:8082", "cert.pem", "key.pem", nil)

	if err != nil {
		panic(err)
	}
}
