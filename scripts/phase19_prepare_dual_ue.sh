#!/usr/bin/env bash
# Phase19 disposable network ONLY. Creates two genuinely provisioned UE
# identities and two separately configured Docker containers.
set -euo pipefail
test "$ALLOW_PHASE19_DISPOSABLE_LAB" = yes || { echo "Refuse non-lab UE provisioning"; exit 2; }
test -f upstream_open5gs/nr-ue.yaml || exit 2
cd upstream_open5gs
set -a
source .env
set +a
test "$UE1_IMSI" = "001011234567895" || { echo "Unknown subscriber - refuse"; exit 2; }
UE2_IMSI=001011234567896
# The two IMSIs are synthetic lab fixtures, not operator subscribers.
mkdir -p ueransim2
cp ueransim/ueransim-ue.yaml ueransim2/ueransim-ue2.yaml
cp ueransim/ueransim-ue_init.sh ueransim2/ueransim-ue2_init.sh
# The image init script invokes /mnt/ueransim/$COMPONENT_NAME_init.sh;
# mount a separate config dir under that path and override only second IMSI.
cat > nr-ue2.yaml <<'YAML'
services:
  nr_ue2:
    image: docker_ueransim
    container_name: nr_ue2
    stdin_open: true
    tty: true
    volumes:
      - ./ueransim2:/mnt/ueransim
      - /etc/localtime:/etc/localtime:ro
    env_file:
      - .env
    environment:
      - COMPONENT_NAME=ueransim-ue2
      - UE1_IMSI=001011234567896
    expose:
      - "4997/udp"
    cap_add:
      - NET_ADMIN
    privileged: true
    networks:
      default:
        ipv4_address: 172.22.0.38
networks:
  default:
    external: true
    name: docker_open5gs_default
YAML
docker exec webui /open5gs/misc/db/open5gs-dbctl add_ue_with_apn \
    "$UE2_IMSI" "$UE1_KI" "$UE1_OP" internet
docker compose -f nr-ue2.yaml config --quiet
echo "Two separate synthetic UERANSIM UE configurations and subscriptions prepared."
