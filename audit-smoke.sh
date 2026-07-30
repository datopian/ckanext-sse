#!/usr/bin/env bash
# Drives every API audit event against the local dev CKAN and prints what the
# plugin emitted. Creates a throwaway token, uses it, revokes it, reuses it.
set -uo pipefail

CKAN_URL=${CKAN_URL:-http://localhost:5000}
CONTAINER=${CONTAINER:-ssen-ckan-dev}
INI=${INI:-/srv/app/ckan.ini}
ADMIN=${ADMIN:-ckan_admin}
NAME="audit-smoke-$$"

api() { # api <action> [json-body] [token]
  local action=$1 body=${2:-} token=${3:-}
  local args=(-s -o /dev/null -w '%{http_code}')
  [ -n "$token" ] && args+=(-H "Authorization: $token")
  if [ -n "$body" ]; then
    args+=(-X POST -H 'Content-Type: application/json' -d "$body")
  fi
  curl "${args[@]}" "$CKAN_URL/api/3/action/$action"
}

START=$(date -u +%s)

echo "==> minting a bootstrap token for $ADMIN"
BOOT=$(docker exec "$CONTAINER" ckan -c "$INI" user token add "$ADMIN" "$NAME-boot" \
        2>/dev/null | tail -1 | tr -d ' \t\r\n')
[ -n "$BOOT" ] || { echo "could not mint token"; exit 1; }

echo -n "  anonymous read            -> "; api status_show
echo -n "  token issue (API)         -> "
TOK=$(curl -s -X POST -H "Authorization: $BOOT" -H 'Content-Type: application/json' \
      -d "{\"user\":\"$ADMIN\",\"name\":\"$NAME\"}" \
      "$CKAN_URL/api/3/action/api_token_create" \
      | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["token"])' 2>/dev/null)
[ -n "$TOK" ] && echo "ok" || { echo "FAILED"; exit 1; }

echo -n "  token read                -> "; api package_list '' "$TOK"
echo -n "  forged token              -> "; api package_list '' "eyJhbGciOiJIUzI1NiJ9.FORGED.x"
echo -n "  basic auth (not a token)  -> "; \
  curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Basic ZGV2OnB3' "$CKAN_URL/api/3/action/status_show"
# Deliberately omits the required `email`, so this 409s and changes nothing --
# the audit line is still emitted, with the password redacted. Sending a valid
# user_update here would really reset the admin password on every run.
echo -n "  secret in params (409)    -> "; api user_update "{\"id\":\"$ADMIN\",\"password\":\"REDACT_ME_PLEASE\"}" "$BOOT"
echo -n "  denied (anonymous write)  -> "; api package_create '{"name":"nope"}'
echo -n "  revoke                    -> "; api api_token_revoke "{\"token\":\"$TOK\"}" "$BOOT"
echo -n "  reuse after revoke        -> "; api package_list '' "$TOK"

# Out of scope: only /api/*/action/* is audited. These must produce no events,
# including the one carrying a token -- scope is the action API, not "/api".
echo -n "  [noise] UI page           -> "; curl -s -o /dev/null -w '%{http_code}\n' "$CKAN_URL/dataset"
echo -n "  [noise] i18n bundle       -> "; curl -s -o /dev/null -w '%{http_code}\n' "$CKAN_URL/api/i18n/en"
echo -n "  [noise] autocomplete      -> "; curl -s -o /dev/null -w '%{http_code}\n' "$CKAN_URL/api/util/dataset/autocomplete?incomplete=a"
echo -n "  [noise] i18n with token   -> "; curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: $BOOT" "$CKAN_URL/api/i18n/en"

echo "==> cleanup"
BOOT_JTI=$(docker exec "$CONTAINER" ckan -c "$INI" user token list "$ADMIN" 2>/dev/null \
           | grep -F "$NAME-boot" | grep -oE '\[[^]]+\]' | tr -d '[]')
[ -n "$BOOT_JTI" ] && docker exec "$CONTAINER" ckan -c "$INI" user token revoke "$BOOT_JTI" >/dev/null 2>&1
echo "  revoked $NAME-boot"

echo
echo "==> events emitted"
docker logs --since "$((  $(date -u +%s) - START + 5 ))s" "$CONTAINER" 2>&1 \
  | grep '"event_type": "security_audit"' \
  | jq -r '[.timestamp[11:19], .action, .status, (.token_auth // "-"),
            (.api_action // "-"), ((.token_id // "-")[0:10]), .user_name,
            (.params // {} | tostring)[0:38]] | @tsv' \
  | column -t -s$'\t'

echo
echo "==> assertions"
LOG=$(docker logs --since "$((  $(date -u +%s) - START + 5 ))s" "$CONTAINER" 2>&1 | grep '"event_type": "security_audit"')
fail=0
want() { # want <description> <jq-filter>
  if echo "$LOG" | jq -s -e "any(.[]; $2)" >/dev/null 2>&1; then echo "  PASS  $1"; else echo "  FAIL  $1"; fail=1; fi
}
want "issuance logged with jti"       '.action=="api_token_issued" and .token_id!=null'
want "revocation logged"              '.action=="api_token_revoked"'
want "live token -> token"            '.token_auth=="token" and .status=="success"'
want "forged token -> token_invalid"  '.token_auth=="token_invalid" and .status=="failure"'
want "revoked reuse -> token_revoked" '.token_auth=="token_revoked" and .status=="failure"'
want "403 -> failure"                 '.api_action=="package_create" and .status=="failure"'
want "password redacted"              '.params.password=="<redacted>"'
want "raw token never logged"         '.params.token=="<redacted>"'
want "validation error logged, not 500" '.api_action=="user_update" and .http_status==409'
echo "$LOG" | grep -q 'REDACT_ME_PLEASE' && { echo "  FAIL  secret leaked into log"; fail=1; } \
                                          || echo "  PASS  secret absent from log"
echo "$LOG" | jq -s -e 'any(.[]; .token_auth=="token_invalid" and .request_path=="/api/3/action/status_show")' >/dev/null 2>&1 \
  && { echo "  FAIL  basic auth mistaken for token"; fail=1; } || echo "  PASS  basic auth not a token"
echo "$LOG" | jq -s -e 'any(.[]; .request_path | test("/action/") | not)' >/dev/null 2>&1 \
  && { echo "  FAIL  non-action request logged"; fail=1; } || echo "  PASS  only action API logged"

exit $fail
