# gapict.com Production TLS Deployment

This environment now uses an automatically managed Let’s Encrypt certificate for `gapict.com`. Follow the steps below whenever you redeploy the server or move it to a new host.

## 1. DNS
- Create **A** records for `gapict.com` and `www.gapict.com` that point to the public IP hosting Spark (currently `72.60.233.29`).
- Set a low TTL (e.g., 300 seconds) while propagating changes so failovers are quick.

## 2. Firewall / Ports
- Allow inbound TCP **80** (Let’s Encrypt HTTP-01 challenge) and **8443** (Spark HTTPS listener defined in `config.json`).
- Outbound HTTPS (port 443) must also be open so the server can reach Let’s Encrypt.

## 3. Server Configuration
`config.json` is already preconfigured:

```json
{
  "listen": ":8443",
  "tls": {
    "enable": true,
    "autocert": {
      "enable": true,
      "domains": ["gapict.com", "www.gapict.com"],
      "email": "admin@gapict.com",
      "cache_dir": "./certs"
    }
  }
}
```

- Ensure the `certs/` directory exists and is writable by the Spark server process so the ACME cache can be stored.
- Run the server as a user that can bind to ports 80 and 8443 (typically root or use `setcap 'cap_net_bind_service=+ep' ./spark-server`).

## 4. Launch / Renewals
Start Spark normally (e.g., `./spark-server -config config.json`). The first run will request certificates for both hostnames and cache them under `./certs`. Certificates renew automatically ~30 days before expiry—no cron jobs required.

## 5. Validation
After the server starts:

```bash
openssl s_client -connect gapict.com:8443 -servername gapict.com -brief
```

You should see a valid chain issued by Let’s Encrypt. Clients must now connect using `https://gapict.com:8443` / `wss://gapict.com:8443/ws`.

## 6. Client Generation
When downloading clients from the Spark UI, set:
- **Host**: `gapict.com`
- **Port**: `8443`
- **Secure**: `true`

The client binaries will trust the public certificate, so no TLS bypass flags are required.
