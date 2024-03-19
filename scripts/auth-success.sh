#! /bin/bash

set -euxo pipefail

./bin/client --client-cert-path certs/client.crt --client-key-path certs/client.key --connect https://tls-flags.research.cloudflare.com --tlsflags 80
