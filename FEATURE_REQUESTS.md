# Feature Requests

## Status-Übersicht

### Bereits implementiert (0.5.0)

- [x] Ergonomische Response-API (`ok`, `text()`, `json()`, `header()`)
- [x] Per-request Timeout (`options.timeout`)
- [x] Per-request Headers (`options.headers`)
- [x] Proxy-Rotation (`proxies: [...]` + Round-Robin)
- [x] Automatische Retries mit Proxy-Rotation (`retries`)
- [x] Bandwidth-Tracking (`bytesSent`, `bytesReceived`, `totalBytesSent()`)
- [x] Request/Response Hooks (`onRequest`, `onResponse`, `onRedirect`)
- [x] Cookie-Jar mit `clearCookies()`
- [x] Fingerprint-Randomisierung (`randomize`)
- [x] Geo-Locale für Accept-Language (`locale`)
- [x] User-Agent exposed (`client.userAgent`)
- [x] String Body (post/put/patch akzeptieren `string | Buffer`)
- [x] Structured Errors (`[CODE] message` + boolean helpers)
- [x] Connection Info (`tls_resumed` + `connection_reused`)
- [x] CONNECT Proxy Headers (`proxyHeaders` für Tunnel-Auth/Session-IDs)
- [x] IPv4/IPv6 Toggle (`ipVersion: 4 | 6`)
- [x] Mobile Browser-Profile (Chrome Mobile, Firefox Mobile, Safari Mobile)
- [x] OkHttp-Profile (Android-App-Impersonation v4/v5)
- [x] Session Persistence (`saveSession`/`loadSession`)
- [x] Streaming Responses (`requestStreaming`)
- [x] WebSocket Support
- [x] Multipart Upload (`postMultipart`)
- [x] MITM Proxy (`KoonProxy`)
- [x] TLS Session Resumption
- [x] DNS-over-HTTPS

---

---

## 2. Fingerprint Self-Test

### Problem

Nutzer können aktuell nicht verifizieren, ob ihr gewähltes Profil tatsächlich dem
echten Browser entspricht. Wenn Akamai oder Cloudflare ein Profil blockt, ist unklar
ob es an einem subtilen TLS-Unterschied liegt.

### Vorschlag

Eingebauter Self-Test, der den eigenen Fingerprint gegen bekannte Referenzdaten prüft:

```javascript
const client = new Koon({ browser: 'firefox147' });
const report = await client.fingerprintCheck();
// {
//   ja3Hash: "abc123...",
//   matchesReference: true,
//   differences: [],
//   h2Fingerprint: "...",
//   headerOrder: [...]
// }
```

Alternativ als CLI-Tool:
```bash
koon fingerprint --browser firefox147
# JA3: abc123...
# H2:  1:65536;2:0;4:6291456;6:262144|...
# Match: firefox 147.0 ✓
```

### Implementierung

- Vergleich gegen gespeicherte Referenz-JA3/JA4-Hashes pro Profil
- Optional: Request an `tls.peet.ws/api/all` oder ähnlichen öffentlichen Endpoint
- Report über Abweichungen (fehlende Extensions, falsche Reihenfolge, etc.)

### Priorität

Mittel. Wertvoll für Debugging und Vertrauensbildung, aber kein Blocker für den Einsatz.
