# Observability (logs, traces, metrics)

This repository now ships a complete, production-ready observability stack blueprint built on OpenTelemetry:

- **Traces:** OTLP → Tempo (or Jaeger)
- **Logs:** OTLP/filelog → Loki (preferred) or any OTLP log backend
- **Metrics:** Prometheus scrape (agents) + OTLP → Prometheus remote_write (Mimir/Thanos)

Use the sample collector config at `observability/otel-collector.yaml` to stand up a single ingestion point.

## Server (Go backend)

- Tracing is **opt-in**. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTLP/HTTP export.
- Optional env:
  - `OTEL_EXPORTER_OTLP_INSECURE=true` for HTTP
  - `OTEL_EXPORTER_OTLP_HEADERS=k1=v1,k2=v2` for auth headers
  - `SPARK_TRACE_SAMPLE_RATIO=0.2` (default 20% parent-based sampler)
- HTTP spans are emitted via `otelgin`; logs include `trace_id`/`span_id` when available.
- Keep existing JSON logs on disk for tailing and filelog shipping.

## Agent (Windows client)

- Metrics and health: served locally at `:9090` (`/metrics`, `/health`, `/ready`) when running as a service.
- Logs: written to `C:\ProgramData\Microsoft\Update\client.log` (or temp fallback). Ship via an OTel Collector/Fluent Bit on the host using filelog/forward. The collector config includes `filelog/agent` with an env override `SPARK_AGENT_LOG_PATH` for custom locations.
- Linux agents: use `filelog/agent_linux` with `SPARK_AGENT_LOG_PATH_LINUX` override; defaults to `/var/log/spark_client.log` and `/opt/spark/logs/client.log`.
- Traces: for now, rely on server spans + correlated logs; collector tails the client log to push into Loki.

## Caddy

Enable JSON access logs with request IDs so the collector can tail and correlate:

```caddyfile
{
  debug
  log {
    format json
    output file /var/log/caddy/access.json {
      roll_size 100MB
      roll_keep 7
    }
  }
}

https://gapict.com:8443 {
  reverse_proxy /api/* http://127.0.0.1:18080
  reverse_proxy /ws http://127.0.0.1:18080
  reverse_proxy /* http://127.0.0.1:18080
}
```

The collector filelog receiver `filelog/caddy` in `observability/otel-collector.yaml` is ready to ingest `/var/log/caddy/access.json`.

## Collector (OTel) topology

 - Receivers: `otlp` (agents + server), `filelog` (server logs, Caddy logs, agent logs on Windows/Linux)
- Processors: `memory_limiter`, `batch`, `resource/defaults`
- Exporters:
  - Traces → `otlp/traces` (Tempo/Jaeger OTLP)
  - Metrics → `prometheusremotewrite` (Mimir/Thanos)
  - Logs → `loki` (preferred)

Start with:

```sh
otelcol-contrib --config observability/otel-collector.yaml \
  --set=OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=tempo:4317 \
  --set=OTEL_EXPORTER_OTLP_TRACES_INSECURE=true \
  --set=LOKI_ENDPOINT=http://loki:3100/loki/api/v1/push \
  --set=PROM_REMOTE_WRITE_ENDPOINT=http://mimir:9009/api/v1/push
```

## Dashboards and alerts (suggested)

- Alerts: repeated 1005/1006 WebSocket closes, UI launch failures, circuit breaker open, missing UI in active session, HTTP 5xx spikes on Caddy/server.
- Dashboards: connection stability (connects/disconnects by code), backoff histograms, session launches/crashes, WS latency, Caddy 4xx/5xx, collector pipeline health.

## No MongoDB required

Use the right backends per signal: Loki for logs, Tempo/Jaeger for traces, Prometheus/Thanos/Mimir for metrics. Avoid generic document stores for telemetry.
