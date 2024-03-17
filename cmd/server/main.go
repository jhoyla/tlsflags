package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	certPath   = flag.String("cert-path", "../../testdata/cert.pem", "path to certificate")
	cAcertPath = flag.String("client-ca-path", "../../testdata/ca.cert.pem", "path to client CA certificate")
	keyPath    = flag.String("key-path", "../../testdata/key.pem", "path to certificate key")
	addr       = flag.String("listen", "localhost:8775", "listening address")
)

func main() {
	flag.Parse()
	cAcertPEM, err := os.ReadFile(*cAcertPath)
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

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("Couldn't load cert")
	}
	config := &tls.Config{
		Certificates:      []tls.Certificate{cert},
		ClientCAs:         clientRootPool,
		TLSFlagsSupported: []tls.TLSFlag{tls.FlagSupportMTLS},
		NextProtos:        []string{"h2"},
	}
	conn, err := tls.Listen("tcp", *addr, config)
	if err != nil {
		log.Fatalf("Couldn't listen on %s", *addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {

		fmt.Fprintf(resp, "Client sent TLS Flags: %v\n", req.TLS.PeerTLSFlags)

		fmt.Fprintf(resp, "Mutually supported TLS Flags: %v\n", req.TLS.AgreedTLSFlags)

		if req.TLS.RequestClientCert {
			fmt.Fprint(resp, "Client cert requested.\n")
		} else {
			fmt.Fprint(resp, "Client cert not requested.\n")
		}

		if len(req.TLS.PeerCertificates) != 0 {
			fmt.Fprintf(resp, "Peer certificate successfully received.\n")
			fmt.Fprintf(resp, "Cert received: %s\n", req.TLS.PeerCertificates[0].DNSNames[0])
			cert := req.TLS.PeerCertificates[0]
			opts := x509.VerifyOptions{
				Roots:     clientRootPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			chains, err := cert.Verify(opts)
			if err != nil {
				log.Print(err)
			}
			if len(chains) != 0 {
				fmt.Fprint(resp, "Cert validated.\n")
			} else {
				fmt.Fprint(resp, "Cert invalid.\n")
			}
		} else {
			fmt.Fprintf(resp, "No Peer certificate received or invalid cert.\n")
		}
	})
	err = http.Serve(conn, mux)
	if err != nil {
		log.Fatalf("Failed to serve")
	}

}
