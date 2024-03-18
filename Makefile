.PHONY: server client

go/bin/go: $(wildcard go/src/*)
	cd go/src/ && ./make.bash


server: cmd/server/main.go go/bin/go
	./go/bin/go build -o ./bin/server ./cmd/server/main.go

client: cmd/client/main.go go/bin/go
	./go/bin/go build -o ./bin/client ./cmd/client/main.go

test: client
	./scripts/normal.sh
	./scripts/otherflags.sh
	./scripts/misconfigured.sh
	./scripts/auth-failure.sh
	./scripts/auth-success.sh
