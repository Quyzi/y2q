#!/bin/sh
# Cluster bring-up entrypoint. Two roles, selected by $ROLE:
#
#   init  -- run once: generate a shared node key into /seed/node.key, then
#            first-run a throwaway non-cluster y2qd against it to generate
#            the shared keystore.json + users.redb (under /seed/keystore/,
#            a sibling of node.key - node_key_file must not resolve inside
#            keystore_dir) and capture the random root password into
#            /seed/root_password.txt. Idempotent.
#
#   node  -- copy the shared keystore into this node's own dir (users.redb is
#            held open per process, so each node needs its own copy, not a
#            shared file), point [crypto] node_key_file at the shared
#            /seed/node.key (read-only mount, same file on every node),
#            render a config.toml, and exec y2qd.
#
# Every node is given the identical node key (the shared-key invariant), so
# every node derives the identical tier-0 keys (index file key, path key,
# object-metadata key) and the cluster admits peers by node-key fingerprint.
set -eu

SEED_DIR=/seed
SEED_KEYSTORE_DIR="$SEED_DIR/keystore"
KEYS_DIR="${Y2QD_CRYPTO__KEYSTORE_DIR:-/var/lib/y2q/keys}"
DATA_DIR="${Y2QD_STORAGE__BASE_PATH:-/var/lib/y2q/data}"
NODE_KEY_FILE="$SEED_DIR/node.key"
PASSWORD_FILE="$SEED_DIR/root_password.txt"
# Reference config shipped in the image; carries the required server/storage/
# crypto/auth sections that have no serde defaults.
BASE_CFG=/etc/y2q/config.toml

# -------------------------------------------------------------------------
# init: generate the shared node key + keystore, capture the root password.
# -------------------------------------------------------------------------
if [ "${ROLE:-node}" = "init" ]; then
    if [ -f "$SEED_KEYSTORE_DIR/keystore.json" ] && [ -f "$NODE_KEY_FILE" ] && [ -f "$PASSWORD_FILE" ]; then
        echo "init: seed node key + keystore already present; nothing to do"
        exit 0
    fi
    mkdir -p "$SEED_KEYSTORE_DIR" /tmp/initdata

    # One shared node key for the whole cluster, generated once. Lives
    # alongside (not inside) $SEED_KEYSTORE_DIR - node_key_file must not
    # resolve inside keystore_dir (see check_node_key_location).
    if [ ! -f "$NODE_KEY_FILE" ]; then
        head -c 32 /dev/urandom > "$NODE_KEY_FILE"
    fi

    # First-run a non-cluster daemon against that node key; it generates the
    # keystore and prints the root password once. Low Argon2 cost so
    # bring-up is fast (demo cluster).
    Y2QD_SERVER__HOST=127.0.0.1 \
    Y2QD_SERVER__PORT=18080 \
    Y2QD_SERVER__TLS__ENABLED=false \
    Y2QD_STORAGE__BASE_PATH=/tmp/initdata \
    Y2QD_CRYPTO__KEYSTORE_DIR="$SEED_KEYSTORE_DIR" \
    Y2QD_CRYPTO__NODE_KEY_FILE="$NODE_KEY_FILE" \
    Y2QD_CRYPTO__ARGON2__M_COST_KIB=8 \
    Y2QD_CRYPTO__ARGON2__T_COST=1 \
    Y2QD_CRYPTO__ARGON2__P_COST=1 \
        /usr/local/bin/y2qd --config "$BASE_CFG" > /tmp/init.log 2>&1 &
    pid=$!

    # Wait for the keystore file and the printed password line.
    i=0
    while [ "$i" -lt 120 ]; do
        if [ -f "$SEED_KEYSTORE_DIR/keystore.json" ] && grep -q 'password:' /tmp/init.log 2>/dev/null; then
            break
        fi
        i=$((i + 1))
        sleep 1
    done

    # The banner line is "    password: <token>"; the token has no spaces.
    pw="$(grep 'password:' /tmp/init.log 2>/dev/null | head -1 | awk '{print $NF}')"
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    if [ -z "$pw" ] || [ ! -f "$SEED_KEYSTORE_DIR/keystore.json" ]; then
        echo "init: FAILED to generate keystore; daemon log follows:" >&2
        cat /tmp/init.log >&2 || true
        exit 1
    fi
    printf '%s' "$pw" > "$PASSWORD_FILE"
    echo "init: node key + keystore + root password written to $SEED_DIR"
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
# process lifetime, so a shared file would contend / corrupt). The node key
# itself is read directly from the read-only /seed mount - no per-node copy.
if [ ! -f "$KEYS_DIR/keystore.json" ]; then
    cp "$SEED_KEYSTORE_DIR/keystore.json" "$SEED_KEYSTORE_DIR/users.redb" "$KEYS_DIR/"
fi

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
export Y2QD_CRYPTO__NODE_KEY_FILE="$NODE_KEY_FILE"
export Y2QD_SERVER__PORT="$PORT"
export Y2QD_SERVER__TLS__ENABLED=false

echo "node $NODE_ID: starting (advertise $ADVERTISE_ADDR, bootstrap=${BOOTSTRAP:-false})"
exec /usr/local/bin/y2qd --config "$CFG"
