FROM golang:1.24 AS builder

WORKDIR /app

COPY . .
RUN make build


FROM ubuntu:latest

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates

COPY --from=builder /app/bin/user-service .
COPY --from=builder /app/configs ./configs

EXPOSE 50051
CMD ["./user-service"]
