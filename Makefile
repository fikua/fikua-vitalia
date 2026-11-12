.PHONY: test vet fmt build demo sendhook sendhook-bad

# Local demo secrets: throwaway values, only for `make demo`.
DEMO_SECRET ?= local-demo-webhook-secret-0123456789abcdef
DEMO_TOKEN  ?= local-demo-token

test:
	go test -race ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

build:
	go build -o bin/ ./cmd/...

# Runs the platform (http://localhost:8080, admision/pruebas) against the
# local simulator (http://localhost:8090/_sim). Ctrl+C stops both.
demo: build
	@mkdir -p data
	@trap 'kill 0' INT TERM EXIT; \
	VITALIA_WEBHOOK_SECRET=$(DEMO_SECRET) FAKE_TOKEN=$(DEMO_TOKEN) ./bin/fakeadapter & \
	VITALIA_WEBHOOK_SECRET=$(DEMO_SECRET) VITALIA_ADAPTER_TOKEN=$(DEMO_TOKEN) \
	VITALIA_ADAPTER_BASE_URL=http://localhost:8090 VITALIA_DB_PATH=data/vitalia.db \
	VITALIA_UI_USER=admision VITALIA_UI_PASSWORD=pruebas VITALIA_COOKIE_SECURE=false ./bin/vitalia & \
	wait

# Deployment check. Needs VITALIA_WEBHOOK_SECRET in the environment and URL,
# e.g. make sendhook URL=https://vitalia.fikua.com/webhooks/enrollments
sendhook: build
	./bin/sendhook -url $(URL)

sendhook-bad: build
	./bin/sendhook -bad -url $(URL)
