package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

const (
	certPath = "../../testdata/cert.pem"
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

	keylog, err := os.OpenFile("/tmp/sslkeylogfile", os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalf("couldn't write to sslkeylog: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)
	config := &tls.Config{
		TLSFlagsSupported: []tls.TLSFlag{tls.FlagSupportMTLS},
		RootCAs:           rootPool,
		KeyLogWriter:      keylog,
	}

	log.Printf("TLSFlagsSet conf: %v", config.TLSFlagsSupported)

	_, err = tls.Dial("tcp", "localhost:8775", config)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
