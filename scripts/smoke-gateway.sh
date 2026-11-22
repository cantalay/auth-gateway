#!/usr/bin/env bash
# auth-gateway duman matrisi (deploy sonrası, İP-04 ölçüt 14). Hiçbir sırrı ekrana basmaz.
#
#   scripts/smoke-gateway.sh            # her realm'de yanlış parola → 401, eski /auth/login → 401
#   scripts/smoke-gateway.sh --full     # + todogi tam akış: kayıt → giriş → forgot (202) → reset → yeni parola 200,
#                                       #   eski parola 401, aynı belirteç 410 → geçici kullanıcı silinir
#
# --full sıfırlama belirtecini e-postadan okumak yerine Vault'taki GATEWAY_ACTION_TOKEN_SECRETS ile üretir (gateway'in
# biçimiyle aynı); bunun için `vault login -method=oidc` gerekir. Ortam: GATEWAY (varsayılan https://auth.cantalay.com),
# REALMS, SMOKE_EMAIL_DOMAIN (varsayılan example.com), VAULT_PATH (varsayılan apps/todogi/keycloak),
# ADMIN_SECRET_KEY (varsayılan KEYCLOAK_ADMIN_CLIENT_SECRET), ADMIN_CLIENT_ID (varsayılan auth-gateway-admin).
set -euo pipefail

GATEWAY="${GATEWAY:-https://auth.cantalay.com}"
REALMS="${REALMS:-todogi vitafinder financefollower conquest notify tela}"
DOMAIN="${SMOKE_EMAIL_DOMAIN:-example.com}"
VAULT_PATH="${VAULT_PATH:-apps/todogi/keycloak}"
ADMIN_SECRET_KEY="${ADMIN_SECRET_KEY:-KEYCLOAK_ADMIN_CLIENT_SECRET}"
ADMIN_CLIENT_ID="${ADMIN_CLIENT_ID:-auth-gateway-admin}"
export VAULT_ADDR="${VAULT_ADDR:-https://vault.cantalay.com}"
full=false
[[ "${1:-}" == "--full" ]] && full=true

fail=0
check() { # ad beklenen gerçek
  if [[ "$2" == "$3" ]]; then printf '  ok    %-48s %s\n' "$1" "$3"; else printf '  HATA  %-48s beklenen %s, gelen %s\n' "$1" "$2" "$3"; fail=1; fi
}
post() { # yol json → HTTP kodu (gövde $tmp/body)
  curl -s -o "$tmp/body" -w '%{http_code}' -X POST "$GATEWAY$1" -H 'Content-Type: application/json' --data-binary @- <<<"$2"
}

umask 077
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
probe="talay-smoke-$(date +%s)-$RANDOM@$DOMAIN"

echo "giriş matrisi ($GATEWAY)"
for realm in $REALMS; do
  check "/auth/$realm/login yanlış parola" 401 "$(post "/auth/$realm/login" "{\"email\":\"$probe\",\"password\":\"Yanlis-Parola-1!\"}")"
done
check "/auth/login (eski yol) yanlış parola" 401 "$(post /auth/login "{\"email\":\"$probe\",\"password\":\"Yanlis-Parola-1!\"}")"
check "/auth/vitafinder/forgot-password kapalı" 404 "$(post /auth/vitafinder/forgot-password "{\"email\":\"$probe\"}")"

if $full; then
  echo "todogi tam akış"
  vault token lookup >/dev/null 2>&1 || { echo "Vault girişi yok: vault login -method=oidc" >&2; exit 1; }
  email="talay-smoke-$(date +%s)-$RANDOM@$DOMAIN"
  pw1="Smoke-$(openssl rand -hex 6)-A1!"; pw2="Smoke-$(openssl rand -hex 6)-B2!"
  check "register" 201 "$(post /auth/todogi/register "{\"email\":\"$email\",\"password\":\"$pw1\",\"firstName\":\"Talay\",\"lastName\":\"Smoke\",\"locale\":\"tr\"}")"
  check "login" 200 "$(post /auth/todogi/login "{\"email\":\"$email\",\"password\":\"$pw1\"}")"
  check "forgot-password" 202 "$(post /auth/todogi/forgot-password "{\"email\":\"$email\"}")"
  vault kv get -mount=kv -field=GATEWAY_ACTION_TOKEN_SECRETS "$VAULT_PATH" > "$tmp/keys"
  vault kv get -mount=kv -field="$ADMIN_SECRET_KEY" "$VAULT_PATH" > "$tmp/admin"
  # Belirteç: gateway ActionTokenService biçimi; parmak izi parola kimlik bilgisinden (admin API).
  EMAIL="$email" GATEWAY="$GATEWAY" CLIENT="$ADMIN_CLIENT_ID" TMP="$tmp" python3 - <<'PY'
import base64, hashlib, hmac, json, os, time, urllib.parse, urllib.request
tmp, base = os.environ["TMP"], os.environ["GATEWAY"]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": os.environ["CLIENT"],
                               "client_secret": open(f"{tmp}/admin").read().strip()}).encode()
with urllib.request.urlopen(f"{base}/realms/todogi/protocol/openid-connect/token", form) as r:
    admin = json.load(r)["access_token"]
def get(path):
    req = urllib.request.Request(f"{base}/admin/realms/todogi{path}", headers={"Authorization": f"Bearer {admin}"})
    with urllib.request.urlopen(req) as r: return json.load(r)
user = get("/users?exact=true&email=" + urllib.parse.quote(os.environ["EMAIL"]))[0]
cred = next(c for c in get(f"/users/{user['id']}/credentials") if c["type"] == "password")
fp = b64(hashlib.sha256("\n".join(["password", cred["id"], str(cred["createdDate"])]).encode()).digest())
kid, secret = open(f"{tmp}/keys").read().strip().split(",")[0].split(":", 1)
payload = json.dumps({"v": 1, "kid": kid, "realm": "todogi", "purpose": "reset", "sub": user["id"],
                      "exp": int(time.time()) + 600, "fp": fp}, separators=(",", ":")).encode()
body = b64(payload)
try:  # gateway: standard base64 first, then URL-safe
    key = base64.b64decode(secret, validate=True)
except ValueError:
    key = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
sig = hmac.new(key, body.encode(), hashlib.sha256).digest()
open(f"{tmp}/token", "w").write(body + "." + b64(sig))
open(f"{tmp}/uid", "w").write(user["id"])
open(f"{tmp}/admintoken", "w").write(admin)
PY
  rm -f "$tmp/keys" "$tmp/admin"
  token="$(cat "$tmp/token")"
  check "reset-password/check" 204 "$(post /auth/todogi/reset-password/check "{\"token\":\"$token\"}")"
  check "reset-password" 200 "$(post /auth/todogi/reset-password "{\"token\":\"$token\",\"newPassword\":\"$pw2\"}")"
  check "login eski parola" 401 "$(post /auth/todogi/login "{\"email\":\"$email\",\"password\":\"$pw1\"}")"
  check "login yeni parola" 200 "$(post /auth/todogi/login "{\"email\":\"$email\",\"password\":\"$pw2\"}")"
  check "reset-password aynı belirteç" 410 "$(post /auth/todogi/reset-password "{\"token\":\"$token\",\"newPassword\":\"$pw1\"}")"
  code="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$GATEWAY/admin/realms/todogi/users/$(cat "$tmp/uid")" \
    -H "Authorization: Bearer $(cat "$tmp/admintoken")")"
  check "geçici kullanıcı silindi" 204 "$code"
fi

[[ $fail == 0 ]] && echo "duman matrisi geçti" || { echo "duman matrisinde hata var" >&2; exit 1; }
