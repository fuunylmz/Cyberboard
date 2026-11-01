#!/bin/bash
# M1 end-to-end acceptance: admin bootstrap → config publish → agent apply → rollback
set -euo pipefail

cd "$(dirname "$0")"

DB_NAME=cyberboard_e2e_m1
ADMIN_EMAIL=e2e-admin@example.test
ADMIN_PASSWORD=e2e-test-password-12345
API_PORT=28080
GRPC_PORT=29090
AGENT_DIR=$(mktemp -d)
AGENT_IDENTITY="$AGENT_DIR/identity.json"
AGENT_CONFIG="$AGENT_DIR/config.json"

trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$AGENT_DIR"' EXIT

echo "=== M1 E2E: creating database $DB_NAME"
PGPASSWORD=$(cat .worktrees/pg.pw) psql -h 127.0.0.1 -p 55432 -U cyberboard postgres -c "DROP DATABASE IF EXISTS $DB_NAME" || true
PGPASSWORD=$(cat .worktrees/pg.pw) psql -h 127.0.0.1 -p 55432 -U cyberboard postgres -c "CREATE DATABASE $DB_NAME"

export CYBERBOARD_DATABASE_URL="postgres://cyberboard:$(cat .worktrees/pg.pw)@127.0.0.1:55432/$DB_NAME"
export CYBERBOARD_DEV_MODE=1
export CYBERBOARD_BIND_ADDR=127.0.0.1
export CYBERBOARD_API_PORT=$API_PORT
export CYBERBOARD_AGENT_GRPC_ADDR=127.0.0.1:$GRPC_PORT
export CYBERBOARD_BOOTSTRAP_ADMIN_EMAIL="$ADMIN_EMAIL"
export CYBERBOARD_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASSWORD"
export RUST_LOG=info,cyberboard_agent=debug

echo "=== Building API + Agent"
cargo build -p cyberboard-api -p cyberboard-agent --offline

echo "=== Starting API (bootstrap will run)"
target/debug/cyberboard-api 2>&1 | tee /tmp/e2e-api.log &
API_PID=$!
sleep 3

echo "=== Admin login"
ADMIN_TOKEN=$(curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .token)
echo "Admin token: ${ADMIN_TOKEN:0:20}..."

echo "=== Creating node"
NODE_RESPONSE=$(curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/nodes \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"e2e-node","region":"test","address":"127.0.0.1","port":10800,"core":"sing-box","coreVersion":"1.14.4","agentVersion":"0.1.0"}')
NODE_ID=$(echo "$NODE_RESPONSE" | jq -r .id)
echo "Node ID: $NODE_ID"

echo "=== Issuing agent registration token"
REG_RESPONSE=$(curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/nodes/$NODE_ID/agent-registration-token \
  -X POST -H "Authorization: Bearer $ADMIN_TOKEN")
REG_TOKEN=$(echo "$REG_RESPONSE" | jq -r .token)
echo "Registration token: ${REG_TOKEN:0:40}..."

echo "=== Starting Agent"
export CYBERBOARD_CONTROL_PLANE_URL="http://127.0.0.1:$GRPC_PORT"
export CYBERBOARD_AGENT_INSECURE=true
export CYBERBOARD_AGENT_REGISTRATION_TOKEN="$REG_TOKEN"
export CYBERBOARD_NODE_ID="$NODE_ID"
export CYBERBOARD_AGENT_IDENTITY_PATH="$AGENT_IDENTITY"
export CYBERBOARD_AGENT_CONFIG_PATH="$AGENT_CONFIG"
export CYBERBOARD_SING_BOX_BINARY=/opt/homebrew/bin/sing-box
export CYBERBOARD_AGENT_HEALTH_GRACE_MS=2000
export CYBERBOARD_AGENT_INTERVAL_SECS=3

target/debug/cyberboard-agent 2>&1 | tee /tmp/e2e-agent.log &
AGENT_PID=$!
sleep 4

echo "=== Creating config template + revision"
TEMPLATE_RESPONSE=$(curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/config-templates \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"nodeId\":\"$NODE_ID\",\"name\":\"e2e-template\",\"profile\":\"direct\"}")
TEMPLATE_ID=$(echo "$TEMPLATE_RESPONSE" | jq -r .id)
echo "Template ID: $TEMPLATE_ID"

REVISION_RESPONSE=$(curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"templateId\":\"$TEMPLATE_ID\",\"coreType\":\"sing-box\",\"coreVersion\":\"1.14\"}")
REV1_ID=$(echo "$REVISION_RESPONSE" | jq -r .id)
REV1_GEN=$(echo "$REVISION_RESPONSE" | jq -r .generation)
echo "Revision 1 ID: $REV1_ID, generation: $REV1_GEN"

echo "=== Publishing revision 1"
curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions/$REV1_ID/publish \
  -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"expectedGeneration\":$REV1_GEN}" > /dev/null

echo "=== Waiting for Agent to apply (max 15s)"
for i in {1..5}; do
  sleep 3
  REVISIONS=$(curl -sf "http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions?nodeId=$NODE_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  STATUS=$(echo "$REVISIONS" | jq -r '.revisions[0].deploymentStatus // "null"')
  echo "Attempt $i: deployment status = $STATUS"
  if [ "$STATUS" = "applied" ]; then
    echo "✓ Revision 1 applied"
    break
  fi
done

if [ "$STATUS" != "applied" ]; then
  echo "✗ Revision 1 did not reach 'applied'"
  exit 1
fi

echo "=== Checking sing-box is running"
pgrep -f "sing-box run" || { echo "✗ sing-box process not found"; exit 1; }
echo "✓ sing-box running"

echo "=== Creating + publishing revision 2"
REVISION2_RESPONSE=$(curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"templateId\":\"$TEMPLATE_ID\",\"coreType\":\"sing-box\",\"coreVersion\":\"1.14\"}")
REV2_ID=$(echo "$REVISION2_RESPONSE" | jq -r .id)
REV2_GEN=$(echo "$REVISION2_RESPONSE" | jq -r .generation)
echo "Revision 2 ID: $REV2_ID, generation: $REV2_GEN"

curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions/$REV2_ID/publish \
  -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"expectedGeneration\":$REV2_GEN}" > /dev/null

sleep 10
REVISIONS=$(curl -sf "http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions?nodeId=$NODE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
STATUS2=$(echo "$REVISIONS" | jq -r '.revisions[] | select(.generation == '$REV2_GEN') | .deploymentStatus')
echo "Revision 2 status: $STATUS2"
[ "$STATUS2" = "applied" ] || { echo "✗ Revision 2 not applied"; exit 1; }
echo "✓ Revision 2 applied"

echo "=== Rolling back revision 2"
ROLLBACK_RESPONSE=$(curl -sf http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions/$REV2_ID/rollback \
  -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"expectedGeneration\":$REV2_GEN,\"reason\":\"e2e test rollback\"}")
REV3_ID=$(echo "$ROLLBACK_RESPONSE" | jq -r .id)
REV3_GEN=$(echo "$ROLLBACK_RESPONSE" | jq -r .generation)
echo "Rollback created revision $REV3_ID, generation: $REV3_GEN"

sleep 10
REVISIONS=$(curl -sf "http://127.0.0.1:$API_PORT/api/v1/admin/config-revisions?nodeId=$NODE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
STATUS3=$(echo "$REVISIONS" | jq -r '.revisions[] | select(.generation == '$REV3_GEN') | .deploymentStatus')
ROLLBACK_OF=$(echo "$REVISIONS" | jq -r '.revisions[] | select(.generation == '$REV3_GEN') | .rollbackOf')
REV2_STATUS=$(echo "$REVISIONS" | jq -r '.revisions[] | select(.generation == '$REV2_GEN') | .publishStatus')

echo "Revision 3 (rollback) status: $STATUS3, rollbackOf: $ROLLBACK_OF"
echo "Revision 2 publish status: $REV2_STATUS"

[ "$STATUS3" = "applied" ] || { echo "✗ Rollback revision not applied"; exit 1; }
[ "$REV2_STATUS" = "rolled_back" ] || { echo "✗ Revision 2 not marked rolled_back"; exit 1; }
[ "$ROLLBACK_OF" = "$REV1_ID" ] || { echo "✗ Rollback does not point to revision 1"; exit 1; }

echo "✓ Rollback succeeded"
echo "=== M1 E2E PASSED"
