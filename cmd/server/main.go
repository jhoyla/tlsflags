package main

import (
	"log"
	"net/http"
)

const (
	certPath = "../../testdata/cert.pem"
	keyPath  = "../../testdata/key.pem"
)

func main() {

	err := http.ListenAndServeTLS("localhost:8775", certPath, keyPath, nil)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
