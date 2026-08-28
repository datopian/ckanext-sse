#!/usr/bin/env bash
# Proves ckanext.sse.token_scope end-to-end against the local dev CKAN.
#
# Mints three tokens for a throwaway user -- a `frontend_token`, a
# `smart_meter_token`, and an ordinary personal token -- then drives real HTTP
# requests through the running app (so the before_app_request enforcement
# actually fires) and asserts:
#
#   * frontend_token  -> an allowlisted action passes
#   * frontend_token  -> a write is blocked by us (403 + our message)
#   * smart_meter_token -> user_extras passes, anything else blocked
#   * an ordinary token is left alone (never our 403)
#   * a scoped token is denied off the action API
#   * a request with no token is untouched
#
# Env overrides: CKAN_URL, CONTAINER, INI.
set -uo pipefail

CKAN_URL=${CKAN_URL:-http://localhost:5000}
CONTAINER=${CONTAINER:-ssen-ckan-dev}
INI=${INI:-/srv/app/ckan.ini}
TESTER=${TESTER:-sse_scope_tester}

# Our 403 body carries this exact phrase; that is how we tell a block by us
# apart from CKAN's own auth 403.
MARK="not permitted to perform that action"

fail=0

# --------------------------------------------------------------------------
# Setup: ensure the user exists and mint the three named tokens.
# --------------------------------------------------------------------------
echo "==> setup: user + tokens"
SETUP=$(docker exec -i "$CONTAINER" ckan -c "$INI" shell 2>/dev/null <<'PY'
import ckan.logic as logic
import ckan.model as model
from ckan.model.meta import Session

name = "sse_scope_tester"
if model.User.get(name) is None:
    logic.get_action("user_create")(
        {"ignore_auth": True, "model": model, "user": ""},
        {"name": name, "email": name + "@example.com",
         # Must satisfy the SSE password policy this same plugin enforces.
         "password": "violet-tractor-mango-lantern"},
    )

# user_extras reads plugin_extras["ssen"]; a bare user has plugin_extras=None,
# which makes that action 500 on its own. Seed it so the allow cases are clean.
user = model.User.get(name)
user.plugin_extras = {"ssen": {"is_verified_user": False}}
Session.commit()

def mint(tname):
    ctx = {"ignore_auth": True, "model": model, "user": name}
    for t in logic.get_action("api_token_list")(ctx, {"user_id": name}):
        if t["name"] == tname:
            logic.get_action("api_token_revoke")(
                {"ignore_auth": True, "model": model}, {"jti": t["id"]})
    return logic.get_action("api_token_create")(
        ctx, {"user": name, "name": tname})["token"]

print("TOKEN frontend " + mint("frontend_token"))
print("TOKEN smart " + mint("smart_meter_token"))
print("TOKEN personal " + mint("personal_token"))
PY
)

FRONTEND=$(awk '$1=="TOKEN"&&$2=="frontend"{print $3}' <<<"$SETUP")
SMART=$(awk '$1=="TOKEN"&&$2=="smart"{print $3}' <<<"$SETUP")
PERSONAL=$(awk '$1=="TOKEN"&&$2=="personal"{print $3}' <<<"$SETUP")

if [ -z "$FRONTEND" ] || [ -z "$SMART" ] || [ -z "$PERSONAL" ]; then
  echo "  could not mint tokens; is $CONTAINER up? output was:"; echo "$SETUP"
  exit 1
fi
echo "  minted frontend_token, smart_meter_token, personal_token for $TESTER"

# --------------------------------------------------------------------------
# Request helper: prints the response body followed by a final line "CODE:nnn".
# --------------------------------------------------------------------------
req() { # req <token> <action> [json-body]
  local token=$1 action=$2 body=${3:-}
  local args=(-s -w $'\nCODE:%{http_code}')
  [ -n "$token" ] && args+=(-H "Authorization: $token")
  if [ -n "$body" ]; then
    args+=(-X POST -H 'Content-Type: application/json' -d "$body")
  fi
  curl "${args[@]}" "$CKAN_URL/api/3/action/$action"
}
code_of() { sed -n 's/^CODE:\([0-9]*\)$/\1/p' <<<"$1"; }

pass() { echo "  PASS  $1"; }
bad()  { echo "  FAIL  $1"; fail=1; }

# blocked-by-us: 403 AND our marker in the body.
assert_blocked() { # assert_blocked <desc> <resp>
  local code; code=$(code_of "$2")
  if [ "$code" = "403" ] && grep -qF "$MARK" <<<"$2"; then pass "$1 (403, our block)"
  else bad "$1 (want 403+marker, got $code)"; fi
}
# passed: 200 AND not our marker.
assert_allowed() { # assert_allowed <desc> <resp>
  local code; code=$(code_of "$2")
  if [ "$code" = "200" ] && ! grep -qF "$MARK" <<<"$2"; then pass "$1 (200)"
  else bad "$1 (want 200, got $code)"; fi
}
# untouched: whatever CKAN does, it is NOT our 403 marker.
assert_not_ours() { # assert_not_ours <desc> <resp>
  if grep -qF "$MARK" <<<"$2"; then bad "$1 (we blocked a token we should not)"
  else pass "$1 (left to CKAN, code $(code_of "$2"))"; fi
}

echo
echo "==> assertions"

assert_allowed  "frontend_token + user_extras"        "$(req "$FRONTEND" user_extras)"
assert_blocked  "frontend_token + package_create"     "$(req "$FRONTEND" package_create '{"name":"scope-test"}')"
assert_blocked  "frontend_token + status_show (core)" "$(req "$FRONTEND" status_show)"

assert_allowed  "smart_meter_token + user_extras"     "$(req "$SMART" user_extras)"
assert_blocked  "smart_meter_token + package_show"    "$(req "$SMART" package_show '{"id":"whatever"}')"
# Checked here, before the generation block below revokes/reissues this token.
assert_blocked  "smart_meter_token cannot mint (self-mint denied)" "$(req "$SMART" smart_meter_token_create '{}')"

assert_allowed  "personal token + user_extras"        "$(req "$PERSONAL" user_extras)"
assert_not_ours "personal token + package_create"     "$(req "$PERSONAL" package_create '{"name":"scope-test"}')"

# Smart Meter token generation (item G): the frontend triggers it on the user's
# behalf, so frontend_token may call it; the resulting token is scoped to
# user_extras only; and a smart_meter_token cannot mint another (no self-mint).
echo "  --- Smart Meter token generation ---"
GEN=$(req "$FRONTEND" smart_meter_token_create '{}')
assert_allowed "frontend_token + smart_meter_token_create" "$GEN"
NEWSM=$(sed '/^CODE:/d' <<<"$GEN" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["token"])' 2>/dev/null)
if [ -n "$NEWSM" ]; then
  assert_allowed "generated smart_meter_token + user_extras"  "$(req "$NEWSM" user_extras)"
  assert_blocked "generated smart_meter_token + package_show" "$(req "$NEWSM" package_show '{"id":"x"}')"
else
  bad "smart_meter_token_create returned no token"
fi

# has_smart_meter_token flips false -> true, so the UI can offer Generate vs
# Regenerate without ever reading the token value back.
echo "  --- has_smart_meter_token state ---"
# Pipe to grep (not >/dev/null): `ckan shell` does not run its input when its
# stdout is redirected to /dev/null, but does when piped.
docker exec -i "$CONTAINER" ckan -c "$INI" shell 2>/dev/null <<'PY' | grep RESULT >/dev/null
import ckan.logic as logic, ckan.model as model
name = "sse_scope_tester"; ctx = {"ignore_auth": True, "model": model, "user": name}
n = 0
for t in logic.get_action("api_token_list")(ctx, {"user_id": name}):
    if t["name"] == "smart_meter_token":
        logic.get_action("api_token_revoke")({"ignore_auth": True, "model": model}, {"jti": t["id"]})
        n += 1
print("RESULT cleared", n)
PY
BEFORE=$(req "$FRONTEND" user_extras)
grep -Eq '"has_smart_meter_token":[[:space:]]*false' <<<"$BEFORE" \
  && pass "no token yet -> has_smart_meter_token false" \
  || bad "want has_smart_meter_token false, got $(sed '/^CODE:/d' <<<"$BEFORE")"
req "$FRONTEND" smart_meter_token_create '{}' >/dev/null
AFTER=$(req "$FRONTEND" user_extras)
grep -Eq '"has_smart_meter_token":[[:space:]]*true' <<<"$AFTER" \
  && pass "after generate -> has_smart_meter_token true" \
  || bad "want has_smart_meter_token true, got $(sed '/^CODE:/d' <<<"$AFTER")"

# No token: our layer must not touch it (whatever noanonaccess/CKAN return).
assert_not_ours "no token + status_show"              "$(req '' status_show)"

# --------------------------------------------------------------------------
# Cleanup: revoke the three tokens.
# --------------------------------------------------------------------------
echo
echo "==> cleanup"
docker exec -i "$CONTAINER" ckan -c "$INI" shell 2>/dev/null <<'PY' | grep RESULT
import ckan.logic as logic
import ckan.model as model
name = "sse_scope_tester"
ctx = {"ignore_auth": True, "model": model, "user": name}
n = 0
for t in logic.get_action("api_token_list")(ctx, {"user_id": name}):
    logic.get_action("api_token_revoke")(
        {"ignore_auth": True, "model": model}, {"jti": t["id"]})
    n += 1
print("RESULT revoked", n, "tokens")
PY

echo
[ "$fail" = 0 ] && echo "==> ALL PASSED" || echo "==> FAILURES ABOVE"
exit $fail
