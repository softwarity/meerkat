# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26
ARG NODE_VERSION=24

# The console first: its production build is embedded in the Go binary, so the
# image needs nothing but the binary itself.
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

# An empty /data owned by the runtime user. Distroless has no shell, so the
# directory is built here and copied in — and Docker gives a fresh volume
# mounted over it the SAME ownership, which is what lets a nonroot process
# write to it.
FROM busybox:stable AS datadir
RUN mkdir -p /seed/data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /meerkat /meerkat
COPY --from=datadir --chown=nonroot:nonroot /seed/data /data
# ABSOLUTE, and that is the whole point. The flag's default is the RELATIVE
# path "data", which resolves against the working directory — /home/nonroot in
# this image. The database therefore landed in the container's own layer while
# a volume sat unused on /data: every restart came back to a blank gateway,
# re-seeded from the configuration file, with the console's work gone. Nothing
# in the logs said so, because nothing was wrong from the binary's side.
ENV MEERKAT_DATA=/data
VOLUME ["/data"]
ENTRYPOINT ["/meerkat"]
