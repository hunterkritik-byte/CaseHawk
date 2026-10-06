FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /casehawk ./cmd/casehawk

FROM alpine:3.22
RUN adduser -D -H casehawk && mkdir -p /data/evidence && chown -R casehawk:casehawk /data
USER casehawk
COPY --from=build /casehawk /casehawk
EXPOSE 8080
ENTRYPOINT ["/casehawk"]
