FROM alpine:3.19
RUN apk add --no-cache curl
COPY app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]
