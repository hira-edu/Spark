# Logging guide

This project now emits more detailed server-side logs by default. Use the following tips to collect end-to-end traces across the stack when debugging connectivity issues.

For the full OpenTelemetry stack (logs + traces + metrics), see `docs/observability.md` and the reference collector config at `observability/otel-collector.yaml`.

## Spark server (Go backend)

- HTTP requests are logged with method, path, status, latency, UA, origin, and whether they attempted an Upgrade.
- Desktop WebSocket handshakes log both success and failure reasons (missing query params, bad origin, bad secret, device not found, etc.).
- Logs are written to `./logs/<date>.log` (see `config.json` for log path/retention). Tail with:
  ```sh
  tail -f logs/$(date +%F).log
  ```

## Caddy reverse proxy

Enable detailed access/error logs to capture reverse-proxy and WebSocket upgrade failures:

```caddyfile
{
  debug
  order webSockets before reverse_proxy
  # optional: log default JSON
  log {
    output file /var/log/caddy/access.log {
      roll_size 100MB
      roll_keep 5
    }
    format json
    level DEBUG
  }
}

https://gapict.com:8443 {
  reverse_proxy /api/* http://127.0.0.1:18080 {
    header_up Host {upstream_hostport}
    header_up X-Real-IP {remote}
    header_up X-Forwarded-For {remote}
  }
  reverse_proxy /ws http://127.0.0.1:18080
  reverse_proxy /* http://127.0.0.1:18080
}
```

After reloading Caddy, inspect `/var/log/caddy/access.log` for 4xx/5xx or failed upgrade attempts.

## Agent (client) logging

Run the agent in the foreground and capture stdout/stderr when debugging:

```sh
./spark-client -config ./client.json 2>&1 | tee client.log
```

If running as a service, ensure your service manager keeps stdout/stderr (e.g., `journalctl -u spark-client` for systemd).
