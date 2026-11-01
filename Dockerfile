FROM golang:1.27.3-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download all && go mod verify
COPY . .
RUN go mod download all && go mod verify \
    && CGO_ENABLED=0 GOOS=linux go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/zentcal ./cmd/zentcal

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata postgresql-client openssh-client sshpass
WORKDIR /app
COPY --from=build /out/zentcal /app/zentcal
COPY web /app/web
RUN addgroup -S zentcal && adduser -S -G zentcal -h /app zentcal \
    && mkdir -p /data/backups /data/tmp /data/ssh \
    && chown -R zentcal:zentcal /app /data
USER zentcal
EXPOSE 8080
ENTRYPOINT ["/app/zentcal"]
