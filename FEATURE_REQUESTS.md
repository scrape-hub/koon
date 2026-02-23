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
- [x] Session Persistence (`saveSession`/`loadSession`)
- [x] Streaming Responses (`requestStreaming`)
- [x] WebSocket Support
- [x] Multipart Upload (`postMultipart`)
- [x] MITM Proxy (`KoonProxy`)
- [x] TLS Session Resumption
- [x] DNS-over-HTTPS

---

## 1. Mobile Browser-Profile

### Problem

Aktuell unterstützt koon nur Desktop-Browser-Profile (Chrome, Firefox, Safari, Edge, Opera).
Für Web-Scraping mit Residential-Proxies sind mobile Profile eine natürliche Ergänzung:

- **Residential IPs + Mobile User-Agent = plausibel.** Viele echte Nutzer surfen mobil über Heim-WLAN.
- **Mehr Ausweichmöglichkeiten bei Fingerprint-Blocking.** Wenn ein WAF (z.B. Akamai) Desktop-Chrome-Profile blockt, könnten Mobile-Chrome oder Mobile-Safari durchkommen — anderer TLS-Fingerprint, anderer HTTP/2-Handshake.
- **Breiterer Fingerprint-Pool.** Mehr verschiedene Profile = schwerer zu fingerprint-basiert zu blocken.
- **Realer Marktanteil.** Mobile Traffic ist >50% des Web-Traffics. Ein HTTP-Client ohne Mobile-Profile ist unvollständig.

### Vorschlag

Neue Profile neben den bestehenden Desktop-Varianten:

```typescript
type Browser =
  // Bestehend (Desktop)
  | 'chrome' | 'chrome145' | 'firefox' | 'firefox147' | 'safari' | 'safari183'
  // Neu (Mobile)
  | 'chrome-mobile' | 'chrome-mobile145'     // Android Chrome
  | 'safari-mobile' | 'safari-mobile183'     // iOS Safari
  | 'firefox-mobile' | 'firefox-mobile147'   // Android Firefox
  // OS-Varianten (bestehend)
  | `${string}-windows` | `${string}-macos` | `${string}-linux`
  // Neu: Mobile OS-Varianten
  | `${string}-android` | `${string}-ios`;
```

### Unterschiede Desktop vs. Mobile

| Aspekt | Desktop | Mobile |
|--------|---------|--------|
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)...` | `Mozilla/5.0 (Linux; Android 14; Pixel 8)...` |
| TLS Extensions | Desktop-spezifische Reihenfolge/Werte | Leicht abweichend (z.B. andere ALPN-Prio) |
| HTTP/2 Settings | Desktop-typische Window-Size etc. | Oft kleinere Werte |
| Sec-CH-UA Hints | `"Chromium";v="145", "Google Chrome";v="145"` | + `Sec-CH-UA-Mobile: ?1`, `Sec-CH-UA-Platform: "Android"` |
| Accept-Language | Oft nur eine Sprache | Oft mit Region (`en-US,en;q=0.9`) |
| Screen-bezogene Headers | Viewport >1024px | Viewport 360-428px |

### TLS-Fingerprint-Quellen

- **ja3.zone / ja3er.com** — JA3-Hashes für Mobile-Browser
- **tls.peet.ws** — Detaillierter TLS-Fingerprint-Vergleich (Desktop vs. Mobile)
- **Wireshark/mitmproxy** — Eigene Captures von echten Mobilgeräten
- **httpbin.org/headers** — Vergleich der Header-Unterschiede

### Priorität

Hoch. Erweitert den Einsatzbereich von koon signifikant für Scraping-Use-Cases mit
Residential-Proxies und verbessert die Resilienz gegen TLS-basiertes Fingerprinting.

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
