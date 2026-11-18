#!/usr/bin/env bash
# Перевірка OCF-системи через HTTP API шлюзу: discovery, security, CRUDN, batch, notify.
G=${G:-http://localhost:8090}
j() { python -c "import sys,json; d=json.load(sys.stdin); print('   ', d.get('code'), '|', d.get('scheme'), '|', json.dumps(d.get('rep'), ensure_ascii=False)[:110])"; }
post() { curl -s -X POST -H 'Content-Type: application/json' -d "$2" "$G$1"; }

echo "== Discovery (multicast ff02::158)"
curl -s -X POST "$G/api/discover" | python -c "import sys,json; [print('   ', d['ip'], d['anchor'], len(d['links']), 'links') for d in json.load(sys.stdin)]"
echo "== Discovery з фільтром rt=oic.r.switch.binary"
curl -s -X POST "$G/api/discover?rt=oic.r.switch.binary" | python -c "import sys,json; [print('   ', d['ip'], [l['href'] for l in d['links']]) for d in json.load(sys.stdin)]"
echo "== Стан безпеки"
curl -s "$G/api/devices" | python -c "import sys,json; [print('   ', d['name'], d['state'], 'owned=', d['doxm']['owned'], 'dtls=', d['secure']) for d in json.load(sys.stdin)]"
echo "== Onboarding (якщо потрібно)"; curl -s -X POST "$G/api/onboard/all"; echo
echo "== RETRIEVE oic.if.baseline (coaps)";            curl -s "$G/api/res/lamp/lamp/switch?if=oic.if.baseline" | j
echo "== RETRIEVE анонімно по coap (ACL anon-clear: R)"; curl -s "$G/api/res/sensor/sensor/temperature?secure=0" | j
echo "== UPDATE анонімно по coap -> 4.01";             post "/api/res/lamp/lamp/switch?secure=0" '{"value":true}' | j
echo "== UPDATE по coaps";                              post "/api/res/lamp/lamp/switch" '{"value":true}' | j
echo "== UPDATE поза діапазоном -> 4.00";               post "/api/res/lamp/lamp/brightness" '{"brightness":150}' | j
echo "== UPDATE read-only (oic.if.s) -> 4.05";          post "/api/res/sensor/sensor/temperature" '{"temperature":5}' | j
echo "== BATCH RETRIEVE (oic.if.b)";                    curl -s "$G/api/res/lamp/lamp?if=oic.if.b" | j
echo "== BATCH UPDATE (oic.if.b)";                      post "/api/res/lamp/lamp?if=oic.if.b" '[{"href":"/lamp/switch","rep":{"value":false}},{"href":"/lamp/brightness","rep":{"brightness":40}}]' | j
echo "== CREATE /plug/schedules (oic.if.create)";       curl -s -X POST "$G/api/schedule" | j
echo "== DELETE останнього розкладу";                   curl -s -X DELETE "$G/api/schedule" | j
echo "== NOTIFY"; curl -s "$G/api/state"; echo
