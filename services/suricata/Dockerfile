FROM alpine:3.23
RUN apk add --no-cache suricata socat

COPY run.sh /run.sh
RUN chmod +x /run.sh

# Bake the rules so the image is self-contained (no runtime mount).
COPY suricata.rules /var/lib/suricata/rules/suricata.rules

WORKDIR /suricata

CMD ["/run.sh"]

