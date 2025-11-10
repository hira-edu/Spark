# Spark Remote Desktop – Network Matrix

This matrix summarizes every network flow used by the Spark remote‑desktop stack today. Use it when preparing firewall rules, proxy policies, or security questionnaires.

| ID | Direction | Purpose | Protocol / Port | Endpoint Pattern | Notes |
|----|-----------|---------|-----------------|------------------|-------|
| NM-01 | Browser ➜ Server | Operator UI + REST APIs (`/api/*`) | HTTPS / TCP 443 (default) | `https://<spark-server-host>:<port>` | Serves the console SPA, authenticates operators, and returns device metadata. |
| NM-02 | Browser ⇄ Server | Remote-desktop WebSocket tunnel | WSS / TCP 443 | `wss://<spark-server-host>/api/device/desktop?device=<id>&secret=<token>` | Carries encrypted control frames, agent telemetry, and diff frames. Establishes from the console once an operator opens the desktop modal. |
| NM-03 | Agent ⇄ Server | Control/telemetry channel | TCP (configurable, default 6060) using Spark’s binary protocol | `<spark-server-host>:<port-from-config>` | Client connects out to the server you operate; no inbound listeners on the agent. All device commands (desktop, terminal, files, etc.) reuse this channel. |
| NM-04 | Agent ➜ Server | Desktop streaming payloads | Same socket as NM-03 | `<spark-server-host>:<port-from-config>` | Desktop frames, clipboard sync, secure hotkey responses, and metrics are multiplexed here. There are no additional media ports (WebRTC/TURN) in the current release. |

### Key Takeaways

1. **All traffic is outbound‑only from the agent.** Spark never opens inbound listeners on managed devices; firewall rules can block unsolicited inbound connections entirely.
2. **Single egress domain/port.** Point the agent at your Spark server (often `console.example.com:6060` or `443`). If you terminate TLS at a reverse proxy, list that hostname/IP in your egress policy.
3. **No TURN/WebRTC yet.** The current desktop pipeline is pure WebSocket/WebTransport. TURN or QUIC endpoints will be added when the WebRTC path ships (tracked separately in the SSOT).
4. **TLS everywhere.** Run both the console and device listeners behind TLS (443) whenever possible so operators and agents traverse corporate proxies without extra allowances.

### Customer-Ready Firewall Language

```
Allow outbound TCP from managed endpoints to <spark-server-host> on port <configured-port>.
Optional: restrict DNS so <spark-server-host> resolves to the Spark control plane.
Block all inbound traffic to the agent; Spark does not require or expose any listening ports.
```

Feel free to copy this paragraph into SOC/security questionnaires. Update the host/port to match the values defined in your `config.json`.
