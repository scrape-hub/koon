# koon — DX Bugfixes & Improvements

Gefunden am 2026-03-23 bei intensiver Nutzung in D:/Projekte/scalable (Signal-Bot mit Proxy-Rotation, Scraping).

## 1. [BUG] Proxy-Auth wird bei HTTP CONNECT ignoriert

**Severity: CRITICAL**

User schreibt `proxy="http://user:pass@proxy.com:8080"` — Credentials werden in `config.rs:58-65` korrekt geparst und in `ProxyConfig::auth` gespeichert, aber in `connection.rs:152-168` beim HTTP CONNECT Tunnel **nie verwendet**. Nur `self.proxy_headers` wird injiziert.

SOCKS5 nutzt `proxy.auth` korrekt (connection.rs:135-140) — HTTP CONNECT nicht.

**Betroffene Dateien:**
- `crates/core/src/proxy/config.rs` — Auth wird geparst (OK)
- `crates/core/src/client/connection.rs:152-168` — Auth wird NICHT angewandt (BUG)

**Fix:**
In `connection.rs` beim HTTP CONNECT automatisch `Proxy-Authorization: Basic base64(user:pass)` aus `proxy.auth` generieren, wenn kein manueller `Proxy-Authorization` Header in `proxy_headers` gesetzt ist.

**Workaround (aktuell nötig):**
```python
import base64
creds = base64.b64encode(b"user:pass").decode()
client = Koon("chrome145",
    proxy="http://user:pass@proxy.com:8080",
    proxy_headers={"Proxy-Authorization": f"Basic {creds}"}
)
```

**Fehlende Tests:**
`crates/core/tests/features.rs` hat Proxy-Tests (Zeile 355, 1141, 1172) aber keinen Test für HTTP CONNECT mit Auth-Credentials in der URL.

---

## 2. [DX] `status` statt `status_code` — Alias fehlt

**Severity: HIGH**

Jeder der von requests/httpx/aiohttp (Python), axios/fetch (Node), httr (R) kommt, tippt `.status_code` und bekommt AttributeError. koon hat nur `.status`.

**Betroffene Dateien:**
- `crates/python/src/lib.rs:604` — `#[pyo3(get)] status: u16`
- `crates/node/src/lib.rs:163` — `status_val: u32` mit Getter `status()`
- `crates/node/index.d.ts:67-99` — TypeScript Definitionen
- `crates/r/R/koon.R` — R Response Klasse

**Fix (Python):**
```rust
// In crates/python/src/lib.rs, KoonResponse impl:
#[getter]
fn status_code(&self) -> u16 {
    self.status
}
```

**Fix (Node):**
```rust
// In crates/node/src/lib.rs, KoonResponse:
#[napi(getter)]
pub fn status_code(&self) -> u32 {
    self.status_val
}
```
Plus TypeScript: `readonly statusCode: number;` in index.d.ts.

**Fix (R):** Property alias in koon.R.

---

## 3. [DX] Python hat keine sync API

**Severity: MEDIUM**

koon Python ist async-only. Jeder `.get()` gibt ein Future zurück, synchroner Code braucht `asyncio.run()` Boilerplate. httpx bietet `Client` (sync) + `AsyncClient` (async).

**Optionen:**
- A) `KoonSync` Wrapper-Klasse die intern `asyncio.run()` macht
- B) `.get_sync()` / `.post_sync()` Methoden auf der bestehenden Klasse
- C) Nichts tun, in Docs dokumentieren (async ist der Standard bei modernem Python)

**Empfehlung:** Option A — `KoonSync` als convenience Wrapper. Viele User (Data Science, Scripting) arbeiten synchron.

---

## 4. [DX] Per-Request Proxy nicht möglich

**Severity: LOW**

Proxy wird im Konstruktor gesetzt. Für unterschiedliche Proxies pro Request muss ein neuer Client erstellt werden. `proxies=[...]` im Konstruktor macht Round-Robin, löst aber nicht "diesen spezifischen Proxy für diesen Request".

**Aktueller Workaround:**
```python
# Neuen Client pro Proxy erstellen
for proxy in proxy_list:
    client = Koon("chrome145", proxy=proxy)
    resp = await client.get(url)
```

**Möglicher Fix:** `proxy` Parameter in `.get()` / `.post()` etc. — aber das erfordert tiefere Änderungen im Connection Pool (proxy-aware).

**Empfehlung:** Low priority. `proxies=[...]` Round-Robin deckt 90% der Use-Cases ab. Per-Request wäre nice-to-have.

---

## Priorität

| # | Was | Aufwand | Impact |
|---|-----|---------|--------|
| 1 | Proxy-Auth CONNECT Bug | ~30 Min | Kritisch — jeder HTTP-Proxy-User betroffen |
| 2 | status_code Alias | ~15 Min | Hoch — Migration von requests/httpx |
| 3 | Sync API | ~2-4h | Mittel — Convenience |
| 4 | Per-Request Proxy | ~1 Tag | Niedrig — Workaround existiert |
