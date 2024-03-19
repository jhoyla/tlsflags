#! /bin/bash

set -euxo pipefail

./bin/client --client-cert-path certs/bad-client.crt --client-key-path certs/bad-client.key --connect https://tls-flags.research.cloudflare.com --tlsflags 80
