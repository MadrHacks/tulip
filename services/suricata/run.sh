#!/usr/bin/env sh

SURICATA_PARAMS="-c /etc/suricata/suricata.yaml \
  --pcap-file-continuous \
  --set runmode=single \
  --set outputs.0.fast.enabled=false \
  --set outputs.1.eve-log.enabled=true \
  --set outputs.1.eve-log.filetype=redis \
  --set outputs.1.eve-log.redis.server=${REDIS_HOST} \
  --set outputs.1.eve-log.redis.port=${REDIS_PORT} \
  --set outputs.7.stats.enabled=false"

set -x

# Pick a live source. REMOTE_CAPTURE_IP (ad-capture broker) takes precedence
# over the classic PCAP_OVER_IP because they're the same wire format (pcap-NG)
# but the broker also carries the Custom Blocks with decrypted plaintext that
# Suricata simply ignores via libpcap — same encrypted-side input either way.
# Either is fine for Suricata; we just need to pick one stream.
if [ -n "$REMOTE_CAPTURE_IP" ]; then
  socat tcp:${REMOTE_CAPTURE_IP} - | suricata ${SURICATA_PARAMS} -r /dev/stdin -v
elif [ -n "$PCAP_OVER_IP" ]; then
  socat tcp:${PCAP_OVER_IP} - | suricata ${SURICATA_PARAMS} -r /dev/stdin -v
else
  suricata ${SURICATA_PARAMS} -r ${TULIP_TRAFFIC_DIR} -v
fi
