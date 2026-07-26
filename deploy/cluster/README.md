# 5-node y2q cluster (docker compose)

Spins up a 5-node `y2qd` cluster: a CRAQ data plane over an embedded raft control
plane. `node1` bootstraps raft and admits `node2`..`node5` as voters
(`voter_seeds = [1,2,3,4,5]`); objects replicate at `replication_factor = 3`.

## Bring it up

```sh
cd deploy/cluster
docker compose up --build        # or: podman compose up --build
```

The `init` service runs once: it generates a single shared node key
(`/seed/node.key`) and, using it, a shared keystore.json + users.redb (so
every node derives identical tier-0 keys - the shared-key invariant) and
captures the random root password. Each node then copies the keystore into
its own volume (the `users.redb` file is held open per process, so it
cannot be shared) and reads the node key directly from the read-only
`/seed` mount, and starts.

Set your own cluster peer secret instead of the default:

```sh
echo 'CLUSTER_SECRET=a-long-random-shared-secret' > .env
docker compose up --build
```

## Endpoints

| Node | Host port | In-cluster address |
|------|-----------|--------------------|
| node1 (bootstrap) | http://localhost:8080 | node1:8080 |
| node2 | http://localhost:8081 | node2:8080 |
| node3 | http://localhost:8082 | node3:8080 |
| node4 | http://localhost:8083 | node4:8080 |
| node5 | http://localhost:8084 | node5:8080 |

## Get the root password

```sh
docker compose exec node1 cat /seed/root_password.txt
```

## Try it

```sh
PW=$(docker compose exec -T node1 cat /seed/root_password.txt)

# Log in on any node (user records are shared); grab a token.
TOK=$(curl -s localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d "{\"username\":\"root\",\"password\":\"$PW\"}" | sed 's/.*"token":"//;s/".*//')

# Cluster status (admin): 5 nodes, one leader, the committed epoch.
curl -s localhost:8080/api/v1/cluster/status -H "authorization: Bearer $TOK"

# Write on node1, read back from node3 (apportioned read across the chain).
curl -s -X PUT localhost:8080/demo/hello -H "authorization: Bearer $TOK" --data-binary 'hi from the cluster'
curl -s     localhost:8082/demo/hello -H "authorization: Bearer $TOK"
```

The bucket registry, user records, and object data all converge across the
cluster (bucket/user state via raft; object data via CRAQ chain replication).

## Notes

- TLS and peer auth use a shared secret here for simplicity; production should use
  `cluster.auth = "mtls"` (see `docs/clustering.md`).
- Tear down and wipe state: `docker compose down -v`.
- This uses a shell-bearing image (`deploy/cluster/Dockerfile`, Wolfi base) so one
  image can both generate the node key + keystore and run a node. The plain
  production image (`./Dockerfile`) is distroless.
- Argon2 cost is lowered at keystore generation for fast bring-up; raise it for a
  real deployment.
