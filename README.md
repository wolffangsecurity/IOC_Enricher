<img width="2000" height="1000" alt="image" src="https://github.com/user-attachments/assets/0c183c96-bc8d-469f-a27a-dc5966af2fe5" />


---


A tool for looking up an indicator of compromise (IP address, domain, URL, or file hash) across VirusTotal, AbuseIPDB, and Shodan, checking any CVEs it finds against CISA KEV and EPSS, and producing a 0–100 risk score with the evidence behind it.

An LLM agent decides which lookups to run and which entities to pivot on. Try it on https://ioc-enricher-one.vercel.app/

<img width="964" height="582" alt="Pasted image 20260921122347" src="https://github.com/user-attachments/assets/6440bbab-85f5-4d88-9aef-8a6fff02c403" />




## Features

- **Input types:** IPv4, IPv6, domains, URLs, MD5/SHA-1/SHA-256 hashes, and defanged input such as `hxxp[://]evil[.]com`. Private and bogon addresses are detected locally and skipped, so they don't use API quota.
- **Sources:** VirusTotal, AbuseIPDB, and Shodan are queried concurrently. Results are cached in SQLite (default TTL 24 hours).
<img width="968" height="304" alt="Pasted image 20260921122437" src="https://github.com/user-attachments/assets/0583f10c-8822-4bdd-8b38-89805eef708c" />



- **CVE checks:** CVEs reported by Shodan are matched against CISA KEV and EPSS. Shodan infers CVEs from service banners, so many are false matches; KEV and EPSS help show which ones matter.
- **Scoring:** a deterministic engine produces the 0–100 score with an itemized breakdown. Known CDN and shared-hosting ranges lower the score to reduce false positives.
- **Agent:** a ReAct-style loop (via OpenRouter) plans lookups and pivots. If no model is reachable, scoring still runs without it.
- **Live trace:** agent steps and tool timings stream to the UI over Server-Sent Events.
- **Pivot graph:** the indicator, its ASN, open ports, co-hosted domains, and CVEs, with click-to-pivot.


<img width="1241" height="517" alt="Pasted image 20260921124118" src="https://github.com/user-attachments/assets/b09713ff-5c45-4e02-b608-97007dff1f35" />



- **Bulk mode:** up to 50 indicators per batch, queued to stay within provider rate limits.
- **Phish analyzer:** parses `.eml` files in the browser (routing hops, SPF/DKIM/DMARC results, embedded URLs) and can send extracted indicators to the main investigation view.
<img width="1245" height="577" alt="Pasted image 20260921124716" src="https://github.com/user-attachments/assets/3949c4c1-263b-43cd-91e1-a6c3fbccb08f" />

- **Exports:** draft Microsoft Sentinel KQL queries, Sigma rules, iptables/Pi-hole block commands, STIX 2.1 bundles, and CSV/JSON. Review generated rules and commands before using them.

<img width="1217" height="562" alt="image" src="https://github.com/user-attachments/assets/73b5321d-ac67-44c9-8848-ade90c5bd9be" />
<img width="1217" height="487" alt="image" src="https://github.com/user-attachments/assets/0ee668a0-5f12-4e84-9c45-0faa6b8ed547" />



## How it works

```
Browser (React + TypeScript)
        |  HTTPS / SSE
FastAPI service
  - request filtering, rate limiting, security headers
  - authentication and roles
        |
Agent loop:  plan -> tool call -> pivot -> summarize
  - input/prompt sanitizing, goal and tool allowlists
        |
Providers:  VirusTotal | AbuseIPDB | Shodan | CISA KEV / EPSS
        |
Scoring engine -> SQLite (cache + investigations) -> hash-chained audit log
```

The agent loop, using an example indicator:

```
Thought       Which feeds does this indicator type need?
Action        lookup_virustotal(ioc="43.153.34.199")
Observation   11 malicious, 4 suspicious of 94 engines; ASN 132203
Pivot         Check AbuseIPDB and Shodan for abuse reports and open ports
   ...       (repeats within the limits: 15 tool calls, 2 hops, 30 seconds)
Verdict       Summary with cited evidence; score comes from the scoring engine
```

A lookup goes through these steps:

1. The indicator is normalized and classified. Private and bogon addresses get an immediate benign result.
2. The indicator is checked for injected instructions before it reaches the model.
3. The agent calls provider tools through an argument-validating wrapper.
4. Shodan CVEs are enriched with KEV and EPSS.
5. The scoring engine computes the score and its breakdown from the collected data.
6. Proposed actions are generated. Anything consequential waits for approval.
7. The result is cached, stored, and appended to the audit log.

### Key modules

| File | Purpose |
|---|---|
| `app.py` | FastAPI app, routes, middleware |
| `access_control.py` | Roles and permissions |
| `prompt_firewall.py` | Sanitizes indicators and third-party text before model use |
| `policy_engine.py` | Allowlist of agent goals and tools |
| `tool_guard.py` | Argument validation and secret redaction on tool output |
| `scoring_engine.py` | Deterministic scoring and breakdown |
| `memory_guard.py` | Checks cache writes and keeps revision history |
| `sandbox_executor.py` | Validates generated rules and commands before display |
| `anomaly_detector.py` | Stops runaway agent loops |

## Security design

Indicator data comes from the internet, so the app treats it as hostile. Banners, WHOIS text, and certificate fields can all carry prompt injection.

```
Internet: attacker-controlled data (banners, WHOIS, certificate fields)
   |  boundary 1: request filtering, rate limiting, authentication
Web / API layer
   |  boundary 2: input sanitizing, goal and tool allowlists, output redaction
Agent and tools (read-only)
   |  boundary 3: human approval
Actions: firewall block, case creation
```

- **Untrusted data:** third-party text is sanitized and truncated before it enters the model context. Ports, status codes, and other numeric fields are parsed by code, not by the model.
- **Tool limits:** the agent has four tools (`lookup_virustotal`, `lookup_abuseipdb`, `lookup_shodan`, `evaluate_score`), no shell access, validated arguments, and redacted output. Hard limits: 15 tool calls, 2 pivot hops, 30 seconds per investigation.
- **Read-only by default:** `firewall_block` and `thehive_case` actions require explicit approval. Nothing is applied automatically.
- **Evidence and scoring:** every claim in a verdict must cite a field from a provider. The score comes from the scoring engine, not the model.
- **Audit log:** security events and approvals are written to an append-only JSONL file where each entry includes the SHA-256 hash of the previous one, so edits are detectable.
- **Web layer:** JWT auth with bcrypt password hashing, account lockout after five failed attempts, role-based permissions, rate limiting, standard security headers, and HTML-escaped output.
- A kill switch (`POST /api/security/kill-switch`) stops active agent runs, and `GET /api/security/status` reports subsystem state and audit chain integrity.

