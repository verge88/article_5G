#!/usr/bin/env bash
# Runs on a throwaway GitHub-hosted Ubuntu runner, never on an operator network.
set -euo pipefail
cd upstream_open5gs

# Upstream UERANSIM sample uses OP, while Open5GS DB expects OPc.
python - <<'PY'
from pathlib import Path
from Crypto.Cipher import AES
p=Path(".env")
s=p.read_text()
def value(name):
    return next(ln.split("=",1)[1].strip() for ln in s.splitlines() if ln.startswith(name+"="))
k=bytes.fromhex(value("UE1_KI"))
op=bytes.fromhex(value("UE1_OP"))
opc=bytes(a ^ b for a,b in zip(AES.new(k,AES.MODE_ECB).encrypt(op),op)).hex()
p.write_text("\n".join(
    f"UE1_OP={opc}" if ln.startswith("UE1_OP=") else ln
    for ln in s.splitlines()
)+"\n")
c=Path("ueransim/ueransim-ue.yaml")
src=c.read_text()
assert "opType: 'OP'" in src
c.write_text(src.replace("opType: 'OP'","opType: 'OPC'"))
print("UE and database configured with same OPC; test secret not printed")
PY

docker compose -f sa-deploy.yaml up -d \
    mongo webui nrf scp ausf udr udm pcf bsf nssf amf smf upf
sleep 16
source .env
provisioned=0
for attempt in $(seq 1 12); do
    if docker exec webui /open5gs/misc/db/open5gs-dbctl add_ue_with_apn \
        "$UE1_IMSI" "$UE1_KI" "$UE1_OP" internet; then
        provisioned=1
        break
    fi
    if docker exec -e UE1_IMSI="$UE1_IMSI" -e UE1_KI="$UE1_KI" -e UE1_OP="$UE1_OP" \
       webui bash -lc 'cd /open5gs && misc/db/open5gs-dbctl add_ue_with_apn "$UE1_IMSI" "$UE1_KI" "$UE1_OP" internet'; then
        provisioned=1
        break
    fi
    sleep 4
done
if [[ $provisioned != 1 ]]; then
    echo "Laboratory subscriber provision failed" >&2
    exit 1
fi
docker compose -f nr-gnb.yaml up -d nr_gnb
sleep 12
docker compose -f sa-deploy.yaml ps
docker compose -f nr-gnb.yaml ps
echo "Core, gNB and test subscriber provisioned"
