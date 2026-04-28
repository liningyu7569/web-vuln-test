package http

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
)

var privateKey *rsa.PrivateKey

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
}

func pubKeyHandler(w http.ResponseWriter, r *http.Request) {
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	w.Write(pubPEM)
	fmt.Println("目标请求了公钥")
}

type Payload struct {
	Ciphertext string `json:"ciphertext"`
	Hash       string `json:"hash"`
}

func messageHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var p Payload
	err := json.Unmarshal(body, &p)
	if err != nil {
		fmt.Printf("数据异常 %e\n", err)
		return
	}

	cipherBytes, _ := base64.StdEncoding.DecodeString(p.Ciphertext)
	hash := sha256.Sum256(cipherBytes)
	calculatedHash := hex.EncodeToString(hash[:])

	if calculatedHash != p.Hash {
		fmt.Println("校验失败")
		http.Error(w, "Hash mismatch", http.StatusBadRequest)
		return
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherBytes)
	if err != nil {
		fmt.Println("解密失败:", err)
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}
	fmt.Printf("成功解密出明文内容: %s\n", string(plaintext))
	w.Write([]byte("Server received and decrypted successfully!"))
}

func Do() {
	http.HandleFunc("/public-key", pubKeyHandler)
	http.HandleFunc("/secure-message", messageHandler)

	fmt.Println("http://localhost:8077")
	err := http.ListenAndServe(":8077", nil)
	if err != nil {
		return
	}
}
