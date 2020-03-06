FROM golang:latest AS Builder

RUN mkdir -p /app
COPY . /app
WORKDIR /app
RUN go get

# Build
# CGO_ENABLED, statically links the dependencies, necessary for alpine
# -a forces all the packages to be built into the binary
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-w -s" -a -o go-ioc

FROM golang:alpine

RUN apk add ca-certificates

COPY --from=Builder /app/go-ioc /app/
WORKDIR /app

ENTRYPOINT ["/app/go-ioc"]
CMD ["help"]