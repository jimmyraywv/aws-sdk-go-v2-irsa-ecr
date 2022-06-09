FROM golang:1.18.3 as builder
WORKDIR /
COPY main.go .
COPY go.mod .
COPY go.sum .
# Disable default GOPROXY
RUN go env -w GOPROXY=direct
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o main.bin .

#FROM scratch
FROM alpine:3.16.0
WORKDIR /
COPY --from=builder main.bin main
ENTRYPOINT ["/main"]
