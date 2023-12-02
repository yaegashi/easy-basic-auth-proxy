FROM golang:1.21 as builder
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
WORKDIR /build
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM gcr.io/distroless/static-debian12:latest
USER root
WORKDIR /
COPY --from=builder /build/main /main
EXPOSE 8080
CMD ["/main"]
