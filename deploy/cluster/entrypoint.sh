#!/bin/sh
# Cluster bring-up entrypoint. Two roles, selected by $ROLE:
#
#   init  -- run once: first-run a throwaway non-cluster y2qd to generate the
#            shared deployment keystore (pubkey.json + users.redb) into /seed and
#            capture the random root password into /seed/unlock_secret.txt, which
#            doubles as every node's provisioned MEK unlock secret. Idempotent.
#
#   node  -- copy the shared keystore into this node's own dir (users.redb is held
#            open per process, so each node needs its own copy, not a shared
#            file), render a config.toml, and exec y2qd.
#
# All nodes share one keystore => identical MEK/Path Key (the shared-key
# invariant), so ciphertext is portable between them.
set -eu

SEED_DIR=/seed
KEYS_DIR="${Y2QD_CRYPTO__KEYSTORE_DIR:-/var/lib/y2q/keys}"
DATA_DIR="${Y2QD_STORAGE__BASE_PATH:-/var/lib/y2q/data}"
SECRET_FILE="$SEED_DIR/unlock_secret.txt"
# Reference config shipped in the image; carries the required server/storage/
# crypto/auth sections that have no serde defaults.
BASE_CFG=/etc/y2q/config.toml

# -------------------------------------------------------------------------
# init: generate the shared keystore + capture the root password.
# -------------------------------------------------------------------------
if [ "${ROLE:-node}" = "init" ]; then
    if [ -f "$SEED_DIR/pubkey.json" ] && [ -f "$SECRET_FILE" ]; then
        echo "init: seed keystore already present; nothing to do"
        exit 0
    fi
    mkdir -p "$SEED_DIR" /tmp/initdata

    # First-run a non-cluster daemon; it generates the keystore and prints the
    # root password once. Low Argon2 cost so bring-up is fast (demo cluster).
    Y2QD_SERVER__HOST=127.0.0.1 \
    Y2QD_SERVER__PORT=18080 \
    Y2QD_SERVER__TLS__ENABLED=false \
    Y2QD_STORAGE__BASE_PATH=/tmp/initdata \
    Y2QD_CRYPTO__KEYSTORE_DIR="$SEED_DIR" \
    Y2QD_CRYPTO__ARGON2__M_COST_KIB=8 \
    Y2QD_CRYPTO__ARGON2__T_COST=1 \
    Y2QD_CRYPTO__ARGON2__P_COST=1 \
        /usr/local/bin/y2qd --config "$BASE_CFG" > /tmp/init.log 2>&1 &
    pid=$!

    # Wait for the keystore file and the printed password line.
    i=0
    while [ "$i" -lt 120 ]; do
        if [ -f "$SEED_DIR/pubkey.json" ] && grep -q 'password:' /tmp/init.log 2>/dev/null; then
            break
        fi
        i=$((i + 1))
        sleep 1
    done

    # The banner line is "    password: <token>"; the token has no spaces.
    pw="$(grep 'password:' /tmp/init.log 2>/dev/null | head -1 | awk '{print $NF}')"
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    if [ -z "$pw" ] || [ ! -f "$SEED_DIR/pubkey.json" ]; then
        echo "init: FAILED to generate keystore; daemon log follows:" >&2
        cat /tmp/init.log >&2 || true
        exit 1
    fi
    printf '%s' "$pw" > "$SECRET_FILE"
    echo "init: keystore + unlock secret written to $SEED_DIR"
    exit 0
fi

# -------------------------------------------------------------------------
# node: copy the keystore, render config, run.
# -------------------------------------------------------------------------
: "${NODE_ID:?NODE_ID is required for a node}"
: "${ADVERTISE_ADDR:?ADVERTISE_ADDR is required for a node}"
PORT="${PORT:-8080}"
RF="${RF:-3}"
VOTER_SEEDS="${VOTER_SEEDS:-1, 2, 3, 4, 5}"

mkdir -p "$KEYS_DIR" "$DATA_DIR"

# Copy the shared keystore once (per-node copy: users.redb is opened for the
# process lifetime, so a shared file would contend / corrupt).
if [ ! -f "$KEYS_DIR/pubkey.json" ]; then
    cp "$SEED_DIR/pubkey.json" "$SEED_DIR/users.redb" "$KEYS_DIR/"
fi

# Provisioned MEK unlock secret = the captured root password.
Y2QD_CLUSTER__UNLOCK_SECRET="$(cat "$SECRET_FILE")"
export Y2QD_CLUSTER__UNLOCK_SECRET

CFG=/tmp/node.toml
# Start from the reference config (server/storage/crypto/auth/observability),
# dropping its trailing [cluster]* sections, then append our cluster config.
# [cluster] is the last section in config.default.toml, so stop printing there.
awk '/^\[cluster\]/{exit} {print}' "$BASE_CFG" > "$CFG"
{
    echo ''
    echo '[cluster]'
    echo 'enabled = true'
    echo "node_id = \"$NODE_ID\""
    echo "advertise_addr = \"$ADVERTISE_ADDR\""
    echo "replication_factor = $RF"
    echo 'unlock = "provisioned"'
    echo 'unlock_user = "root"'
    # Only the bootstrap node lists peers; it admits them after winning election.
    if [ "${BOOTSTRAP:-false}" = "true" ] && [ -n "${PEERS:-}" ]; then
        OLDIFS="$IFS"
        IFS=';'
        for p in $PEERS; do
            echo '[[cluster.peers]]'
            echo "id = ${p%%=*}"
            echo "url = \"${p#*=}\""
        done
        IFS="$OLDIFS"
    fi
    echo '[cluster.raft]'
    echo "bootstrap = ${BOOTSTRAP:-false}"
    echo "voter_seeds = [$VOTER_SEEDS]"
} >> "$CFG"

# Pin paths/port and disable TLS regardless of the reference defaults (env
# overrides the config file in figment, avoiding duplicate TOML sections).
export Y2QD_STORAGE__BASE_PATH="$DATA_DIR"
export Y2QD_CRYPTO__KEYSTORE_DIR="$KEYS_DIR"
export Y2QD_SERVER__PORT="$PORT"
export Y2QD_SERVER__TLS__ENABLED=false

echo "node $NODE_ID: starting (advertise $ADVERTISE_ADDR, bootstrap=${BOOTSTRAP:-false})"
exec /usr/local/bin/y2qd --config "$CFG"
