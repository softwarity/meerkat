# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26
ARG NODE_VERSION=24

# The console first: its production build (one SPA per locale) is embedded
# in the Go binary, so the image needs nothing but the binary itself.
FROM node:${NODE_VERSION}-alpine AS console
WORKDIR /console
COPY console/package.json console/package-lock.json ./
RUN npm ci
COPY console/ ./
RUN npm run build

FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.* ./
RUN go mod download
COPY . .
COPY --from=console /console/dist/console/browser/ internal/admin/ui/dist/
ARG VERSION=dev
ARG GIT_REV=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w \
      -X github.com/softwarity/meerkat/internal/version.Version=${VERSION} \
      -X github.com/softwarity/meerkat/internal/version.Commit=${GIT_REV} \
      -X github.com/softwarity/meerkat/internal/version.Date=${BUILD_DATE}" \
      -o /meerkat ./cmd/meerkat

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /meerkat /meerkat
ENTRYPOINT ["/meerkat"]
