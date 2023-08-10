package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	certPath   = "../../testdata/cert.pem"
	cAcertPath = "../../testdata/ca.cert.pem"
	keyPath    = "../../testdata/key.pem"
	addr       = "localhost:8775"
)

func main() {
	cAcertPEM, err := os.ReadFile(cAcertPath)
	if err != nil {
		log.Fatalf("Couldn't read cert")
	}

	block, rest := pem.Decode(cAcertPEM)
	if len(rest) != 0 {
		log.Fatalf("excess data in cert")
	}

	cAcert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Couldn't parse cert")
	}

	clientRootPool := x509.NewCertPool()
	clientRootPool.AddCert(cAcert)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("Couldn't load cert")
	}
	config := &tls.Config{
		Certificates:      []tls.Certificate{cert},
		ClientCAs:         clientRootPool,
		TLSFlagsSupported: []tls.TLSFlag{tls.FlagSupportMTLS},
		NextProtos:        []string{"h2"},
	}
	conn, err := tls.Listen("tcp", addr, config)
	if err != nil {
		log.Fatalf("Couldn't listen on %s", addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(resp, "Hello world")
	})
	err = http.Serve(conn, mux)
	if err != nil {
		log.Fatalf("Failed to serve")
	}

}
