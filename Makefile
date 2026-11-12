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

# Runs the clinic (http://localhost:8080: website, /profesional, /gestion with
# rrhh / pruebas) against the local simulators (enrolment API, identity
# provider, and http://localhost:8091/_sim). Ctrl+C stops everything.
demo: build
	@mkdir -p data
	@test -f data/demo-signing-key.b64 || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null \
		| openssl pkcs8 -topk8 -nocrypt -outform DER | base64 > data/demo-signing-key.b64
	@trap 'kill 0' INT TERM EXIT; \
	VITALIA_WEBHOOK_SECRET=$(DEMO_SECRET) FAKE_TOKEN=$(DEMO_TOKEN) FAKE_IDP_ISSUER=http://localhost:8091 ./bin/fakeadapter & \
	VITALIA_WEBHOOK_SECRET=$(DEMO_SECRET) VITALIA_ADAPTER_TOKEN=$(DEMO_TOKEN) \
	VITALIA_ADAPTER_BASE_URL=http://localhost:8090 VITALIA_DB_PATH=data/vitalia.db \
	VITALIA_OIDC_ISSUER=http://localhost:8091 VITALIA_OIDC_SIGNING_KEY="$$(cat data/demo-signing-key.b64)" \
	VITALIA_UI_USER=rrhh VITALIA_UI_PASSWORD=pruebas VITALIA_COOKIE_SECURE=false ./bin/vitalia & \
	wait

# Deployment check. Needs VITALIA_WEBHOOK_SECRET in the environment and URL,
# e.g. make sendhook URL=https://vitalia.fikua.com/webhooks/enrollments
sendhook: build
	./bin/sendhook -url $(URL)

sendhook-bad: build
	./bin/sendhook -bad -url $(URL)
