.PHONY: test vet fmt build demo sendhook sendhook-bad authentik-env authentik-up authentik-down authentik-logs demo-authentik

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

# ------------------------------------------------------------- Authentik
# The clinic with its own directory and identity provider (Authentik):
#   make authentik-env    # once: deploy/authentik/.env with random secrets
#   make demo-authentik   # simulators + Vitalia wired to Authentik (terminal 1)
#   make authentik-up     # Authentik on http://localhost:9000 (terminal 2)
# Start demo-authentik first: Authentik reads the DoctorID JWKS from the
# simulator when it applies its blueprint.
AK_DIR := deploy/authentik
AK_ENV := $(AK_DIR)/.env
AK_COMPOSE := docker compose -f $(AK_DIR)/compose.yml --env-file $(AK_ENV)

authentik-env:
	@test ! -f $(AK_ENV) || (echo "$(AK_ENV) already exists"; exit 1)
	@sed -e "s|^PG_PASS=.*|PG_PASS=$$(openssl rand -hex 24)|" \
	     -e "s|^AUTHENTIK_SECRET_KEY=.*|AUTHENTIK_SECRET_KEY=$$(openssl rand -hex 48)|" \
	     -e "s|^AUTHENTIK_BOOTSTRAP_PASSWORD=.*|AUTHENTIK_BOOTSTRAP_PASSWORD=$$(openssl rand -hex 12)|" \
	     -e "s|^VITALIA_CLIENT_SECRET=.*|VITALIA_CLIENT_SECRET=$$(openssl rand -hex 32)|" \
	     -e "s|^VITALIA_PRO_CLIENT_SECRET=.*|VITALIA_PRO_CLIENT_SECRET=$$(openssl rand -hex 32)|" \
	     -e "s|^VITALIA_DIRECTORY_TOKEN=.*|VITALIA_DIRECTORY_TOKEN=$$(openssl rand -hex 32)|" \
	     -e "s|^VITALIA_HR_PASSWORD=.*|VITALIA_HR_PASSWORD=$$(openssl rand -hex 8)|" \
	     -e "s|^ENROLMENT_SCIM_TOKEN=.*|ENROLMENT_SCIM_TOKEN=$$(openssl rand -hex 32)|" \
	     -e "s|^DOCTORID_CLIENT_SECRET=.*|DOCTORID_CLIENT_SECRET=$$(openssl rand -hex 32)|" \
	     $(AK_DIR)/.env.example > $(AK_ENV)
	@chmod 600 $(AK_ENV)
	@echo "Wrote $(AK_ENV). Admin: akadmin / AUTHENTIK_BOOTSTRAP_PASSWORD; HR: rrhh / VITALIA_HR_PASSWORD (both in that file)."

authentik-up:
	$(AK_COMPOSE) up -d

authentik-down:
	$(AK_COMPOSE) down

authentik-logs:
	$(AK_COMPOSE) logs -f --tail=100 server worker

# Like demo, but Vitalia signs in staff and physicians with Authentik, and
# the simulator takes Authentik's SCIM provisioning and DoctorID federation.
demo-authentik: build
	@test -f $(AK_ENV) || (echo "Run make authentik-env first"; exit 1)
	@mkdir -p data
	@test -f data/demo-idp-key.b64 || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null \
		| openssl pkcs8 -topk8 -nocrypt -outform DER | base64 > data/demo-idp-key.b64
	@set -a; . ./$(AK_ENV); set +a; \
	AK_ISSUER=http://localhost:$${COMPOSE_PORT_HTTP:-9000}/application/o/vitalia/; \
	AK_PRO_ISSUER=http://localhost:$${COMPOSE_PORT_HTTP:-9000}/application/o/vitalia-profesional/; \
	trap 'kill 0' INT TERM EXIT; \
	VITALIA_WEBHOOK_SECRET=$(DEMO_SECRET) FAKE_TOKEN=$(DEMO_TOKEN) FAKE_SCIM_TOKEN="$$ENROLMENT_SCIM_TOKEN" \
	FAKE_IDP_ISSUER=http://localhost:8091 FAKE_IDP_SIGNING_KEY="$$(cat data/demo-idp-key.b64)" \
	FAKE_IDP_FED_CLIENT_ID="$$DOCTORID_CLIENT_ID" FAKE_IDP_FED_CLIENT_SECRET="$$DOCTORID_CLIENT_SECRET" \
	FAKE_IDP_FED_REDIRECT_URI=http://localhost:$${COMPOSE_PORT_HTTP:-9000}/source/oauth/callback/doctorid/ \
	./bin/fakeadapter & \
	VITALIA_WEBHOOK_SECRET=$(DEMO_SECRET) VITALIA_ADAPTER_TOKEN=$(DEMO_TOKEN) \
	VITALIA_ADAPTER_BASE_URL=http://localhost:8090 VITALIA_DB_PATH=data/vitalia-authentik.db \
	VITALIA_OIDC_ISSUER=$$AK_PRO_ISSUER VITALIA_OIDC_CLIENT_ID="$$VITALIA_PRO_CLIENT_ID" VITALIA_OIDC_CLIENT_SECRET="$$VITALIA_PRO_CLIENT_SECRET" \
	VITALIA_STAFF_OIDC_ISSUER=$$AK_ISSUER VITALIA_STAFF_OIDC_CLIENT_ID="$$VITALIA_CLIENT_ID" VITALIA_STAFF_OIDC_CLIENT_SECRET="$$VITALIA_CLIENT_SECRET" \
	VITALIA_DIRECTORY_URL=http://localhost:$${COMPOSE_PORT_HTTP:-9000} VITALIA_DIRECTORY_TOKEN="$$VITALIA_DIRECTORY_TOKEN" \
	VITALIA_UI_USER=rrhh VITALIA_UI_PASSWORD=pruebas VITALIA_COOKIE_SECURE=false ./bin/vitalia & \
	wait
