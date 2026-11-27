# syntax=docker/dockerfile:1
#
# Runs as distroless's nonroot user (65532) and reads -config /etc/scep-intune/config.yaml
# by default. See docs/kubernetes.md for the Deployment.

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/scep-intune ./cmd/scep-intune

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="scep-intune" \
      org.opencontainers.image.description="Microsoft Intune SCEP webhook bridge for step-ca" \
      org.opencontainers.image.source="https://github.com/charlespick/scep-intune" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION"
COPY --from=build /out/scep-intune /usr/local/bin/scep-intune
COPY LICENSE /usr/share/doc/scep-intune/LICENSE
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scep-intune"]
CMD ["-config", "/etc/scep-intune/config.yaml"]
