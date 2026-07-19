# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.* ./
RUN go mod download
COPY . .
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
