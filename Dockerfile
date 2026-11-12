# Clínica Vitalia — multi-stage build. Pure Go (modernc.org/sqlite needs no
# cgo), so the binaries are static and run on distroless.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/vitalia ./cmd/sendhook ./cmd/fakeadapter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
ENV VITALIA_LISTEN_ADDR=:8080 VITALIA_DB_PATH=/data/vitalia.db
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/vitalia"]
