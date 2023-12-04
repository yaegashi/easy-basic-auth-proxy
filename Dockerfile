FROM golang:1.21 as builder
ARG BOOTSTRAP_DIST=https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist
ARG CLIPBOARD_DIST=https://cdn.jsdelivr.net/npm/clipboard@2.0.11/dist
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
WORKDIR /build
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p assets
RUN curl -sL ${BOOTSTRAP_DIST}/css/bootstrap.min.css -o assets/bootstrap.min.css
RUN curl -sL ${BOOTSTRAP_DIST}/js/bootstrap.bundle.min.js -o assets/bootstrap.bundle.min.js
RUN curl -sL ${CLIPBOARD_DIST}/clipboard.min.js -o assets/clipboard.min.js
RUN go build -o main .

FROM gcr.io/distroless/static-debian12:latest
USER root
WORKDIR /
COPY --from=builder /build/assets /assets
COPY --from=builder /build/main /main
EXPOSE 8080
CMD ["/main"]
