package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const (
	certPath       = "../../testdata/cert.pem"
	clientCertPath = "../../testdata/client.cert.pem"
	clientKeyPath  = "../../testdata/client.key.pem"
)

func main() {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Couldn't read cert")
	}

	block, rest := pem.Decode(certPEM)
	if len(rest) != 0 {
		log.Fatalf("excess data in cert")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Couldn't parse cert")
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)

	keylog, err := os.OpenFile("/tmp/sslkeylogfile", os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalf("couldn't write to sslkeylog: %v", err)
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		log.Fatalf("couldn't load client cert: %v", err)
	}

	config := &tls.Config{
		TLSFlagsSupported: []tls.TLSFlag{tls.FlagSupportMTLS},
		RootCAs:           rootPool,
		KeyLogWriter:      keylog,
		Certificates:      []tls.Certificate{clientCert},
		NextProtos:        []string{"h2"},
	}

	log.Printf("TLSFlagsSet conf: %v", config.TLSFlagsSupported)

	req, err := http.NewRequest(http.MethodGet, "https://localhost:8775/", nil)
	if err != nil {
		log.Fatal("Could not create request")
	}

	trans := http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true}
	resp, err := trans.RoundTrip(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Couldn't read response body: %v", err)
	}

	fmt.Printf("%s\n", string(respBody))
}
