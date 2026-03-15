FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -o /dnstt-server ./dnstt-server
RUN CGO_ENABLED=0 go build -o /dnstt-client ./dnstt-client

FROM alpine
RUN apk add --no-cache curl
COPY --from=build /dnstt-server /usr/local/bin/
COPY --from=build /dnstt-client /usr/local/bin/
