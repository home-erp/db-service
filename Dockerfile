FROM alpine:3.5
COPY db-service /usr/local/bin/db-service
ENTRYPOINT ["/usr/local/bin/db-service"]
