FROM alpine:3.23
RUN apk add --no-cache suricata socat

COPY run.sh /run.sh
RUN chmod +x /run.sh

WORKDIR /suricata

CMD ["/run.sh"]

