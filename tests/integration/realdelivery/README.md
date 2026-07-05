# Real-delivery integration harness

Stands up Redis + a real ClickHouse + a fake Splunk HEC in containers, replays
the committed pcap fixtures through the two sources, and runs the three sinks in
**real delivery mode** (`--once`, not `--stdout`) so the actual HTTP POST /
`INSERT` / retry / ack-after-2xx / dead-letter paths execute — the coverage the
plain `scripts/run-integration-tests.sh` (stdout mode) cannot provide.

```sh
./run.sh        # build image, up infra, replay, deliver, assert, tear down
```

Requires Docker + the Compose plugin. Runs as the `real-delivery` CI job.

| File | Purpose |
|---|---|
| `Dockerfile` | one image with all five app binaries + fixtures |
| `docker-compose.yml` | redis, clickhouse (schema auto-loaded), hecfake, + the 5 apps |
| `hec_fake.py` | stdlib fake Splunk HEC; records deliveries, optional fail-injection |
| `configs/*.yaml` | per-app configs pointed at the compose service hostnames |
| `run.sh` | orchestration + assertions |

See `docs/integration-harness.md` for the full picture, configuration, and
follow-ups.
