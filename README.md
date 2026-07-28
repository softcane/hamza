# Hamza

![An undercover proxy masking sensitive data before provider egress](assets/hamza-undercover-proxy.png)

*Original artwork for Hamza. The name nods to the undercover operative in
[*Dhurandhar*](https://www.netflix.com/tudum/articles/dhurandhar-release-date-news)
— an apt namesake for a proxy that quietly masks sensitive values before they
reach the Provider.*

**An egress gate for CLI coding agents. It masks secrets and customer data in
the request body before it reaches the model provider, and the agent keeps
working.**

https://github.com/user-attachments/assets/be336248-ba3f-4597-a05c-fb1af8b3124e

A developer types `claude "why did the patient import fail?"`. The agent opens
the failing CSV, reads `.env`, greps the application log, and ships all of it to
`api.anthropic.com` as one JSON body.

Nobody approved that payload. Nobody recorded it. Your DLP saw an HTTPS
connection to a vendor you allowlisted months ago.

Hamza sits between the agent and the provider. It reads the assembled body,
replaces each detected value at its exact span, rebuilds the request, rescans
the rebuild, and releases it.

```text
SOURCE Turn:   patient=priya.fixture@example.com  key=AKIAABCDEFGHIJKLMNOP
DERIVED Turn:  patient=<EMAIL_482191>             key=<SECRET_730044>
```

The model can still tell that two placeholders refer to the same value, so it
keeps reasoning about the bug. It cannot authenticate with a placeholder or
recover the original string.

---

## Why this is an organization problem

Every control you already run inspects a different surface.

| Control | What it watches | What it misses |
|---|---|---|
| Git secret scanning | Committed files | A key the agent read from `.env` and never committed |
| Endpoint DLP | Files, email, USB | A TLS request body your policy already permits |
| CASB / SWG | Browser SaaS sessions | A CLI process posting to an approved API host |
| Code review | Diffs a human wrote | A payload the agent assembled at 2am |

The request body is the gap. It lives for milliseconds, never touches disk, and
no person reviews it before it leaves.

That gap changes what you're exposed to. A vendor that receives ePHI on your
behalf needs a business associate agreement under
[HIPAA](https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html) —
and an agent that reads one patient row while debugging an import job can put
your model provider in that scope with no DPIA on file. A recipient of EU
personal data needs a transfer basis under
[GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj), and an agent that quotes
a customer's email in a prompt creates that recipient. A credential that leaves
in a request body sits in someone else's logs, and you won't know to rotate it
because nothing on your side saw it go. You can't answer "which customer
records went to the model provider last quarter" when no system recorded the
bodies, and you can't honor a deletion request for data you can't enumerate.

None of this is the developer's fault. The person who'd never paste a customer
table into a chat window will ask an agent to debug an import job — the agent
decides what context that takes.

| Industry | What an agent pulls into a Turn | What raw egress changes |
|---|---|---|
| Healthcare | Patient email, phone, medical license, incident logs | The model vendor enters the ePHI processing path and needs a BAA |
| Financial services | Card number, IBAN, account email, support records | The provider enters your handling, retention, and audit boundary for customer financial data |
| SaaS and infrastructure | API keys, tokens, `.env` values, deploy logs | A working credential leaves the network inside a permitted request |
| EU customer operations | Email, phone, IP, customer records | You gain a processing recipient and possibly an international transfer |

Hamza reduces what actually leaves in a masked Turn. Legal basis, contracts,
retention, residency, access control, and incident response still belong to
your compliance program.

---

## How it works

```mermaid
flowchart LR
    A["Claude Code / Codex"] --> E["Envoy"]
    E -->|"complete body over ext_proc"| G["Hamza Gate"]
    G --> D["Secret rulepack + EDM + Presidio"]
    D --> M["Exact-span masking"]
    M --> R["Provider-format rebuild"]
    R --> F["Rescan the rebuild"]
    F -->|"clean"| P["Model Provider"]
    F -->|"gap or residue"| B["Block, zero bytes released"]
    G --> C["Content-free Records and metrics"]
```

1. Envoy sits in front of the provider and hands the Gate the whole request
   body before any of it reaches the network. The Gate reads a fixed, narrow
   set of headers — `Authorization` is never one of them, so provider auth
   passes through without the Gate seeing it.
2. An adapter finds every text segment the provider can read. OpenAI Responses
   and Anthropic Messages are the two supported wire formats.
3. Three detectors run against that text: a 327-rule secret pack, Exact Data
   Match against values you've registered, and Presidio for the PII types on
   its approved profile ([below](#what-it-detects)).
4. Each finding gets one placeholder at its exact span — `<SECRET_1>`,
   `<EMAIL_1>` — and the adapter rebuilds the full request around it.
5. Every detector scans the rebuild again. Only a clean rescan releases it; a
   bad span, malformed JSON, or leftover residue blocks the request and
   releases nothing.

Records keep the action taken, which detector fired, byte counts, and the link
between the original and rebuilt request. They never keep the request content,
the matched values, or provider auth. Each record commits to the one before it,
so an edited history breaks the chain.

Placeholders stand for a **value**, not for the rule that matched it. Two
occurrences of one email render the same placeholder, and two different emails
never render the same one — so the model can still tell what is the same thing
and what isn't. That identity holds within a request on the setup below.

There's also a signed, managed route (see [`CONTEXT.md`](./CONTEXT.md)) that
extends the same placeholder across an entire multi-turn task and pairs every
masked request with an audit record of the original. It needs signed request
metadata, so it's a separate opt-in setup this README doesn't cover. Everything
below runs on the standard route and needs none of it.

### What it detects

| Detector | Scope | Default |
|---|---|---|
| Secret | 327 rules covering cloud, source-control, package, and SaaS credentials | On |
| Exact Data Match | Your registered customer values, stored as one-way fingerprints | On once you load a registry — flags and blocks here, masks on the managed route |
| Presidio | Card, crypto address, email, IBAN, IP, MAC, phone, medical license, URL | On |

The first two only find what they were told to look for. The secret pack
matches credential *shapes*, and Exact Data Match only matches values you
registered in advance. Presidio is the one detector that finds PII nobody
anticipated — which is the whole problem, since the agent decides what context
a task takes. It runs as a separate 2-CPU analyzer container that starts with
the stack, and it only ever sits on the internal network: no published port, no
route off the host.

It costs about a minute of extra start-up while the analyzer warms up, and the
Gate waits for it before accepting traffic. To run without it, set
`HAMZA_PRESIDIO_ENABLED=false` and bring the stack up with `--scale presidio=0`.

Hamza does not enforce person names, locations, dates, nationality, religion,
political affiliation, or free-form medical facts. Each one failed the detector
quality floor, so Presidio never looks for them. Read
[`detector/presidio/approved-profile.json`](./detector/presidio/approved-profile.json)
for the entity set and thresholds. Hamza does not do generic PHI detection.

---

## Run it

### 1. Install

```bash
HAMZA_POSTURE=MASK docker compose up -d --build
```

That brings up Envoy on `10000`, the Gate on `8080`, Prometheus on `9091`, and
Grafana on `3000`, plus the Presidio analyzer on the internal network with no
published port. `HAMZA_POSTURE=MASK` tells the Gate to rewrite bodies instead of
only recording them; drop it to start in `FLAG` (record-only) instead.

The Gate waits for Presidio's health check before it accepts traffic, so the
first boot takes about a minute longer than the containers alone.

Envoy has nowhere to send a request yet — the next step points it at your
provider.

### 2. Point the Gate at your provider

Edit `envoy/envoy.yaml` before routing any real traffic. On `listener_0` (port
`10000`, the port your CLI points at), set the route tag and the upstream
host —

```yaml
# listener_0 -> header_mutation
- append:
    header: { key: x-hamza-route-provider, value: anthropic }   # was: openai

# listener_0 -> route
route:
  cluster: provider_upstream
  host_rewrite_literal: api.anthropic.com
```

— and give `provider_upstream` TLS and a real endpoint:

```yaml
- name: provider_upstream
  type: STRICT_DNS
  connect_timeout: 5s
  common_http_protocol_options: { max_requests_per_connection: 1 }
  transport_socket:
    name: envoy.transport_sockets.tls
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
      sni: api.anthropic.com
  load_assignment:
    cluster_name: provider_upstream
    endpoints:
      - lb_endpoints:
          - endpoint:
              address:
                socket_address: { address: api.anthropic.com, port_value: 443 }
```

Then restart Envoy so it picks up the file:

```bash
docker compose restart envoy
```

Envoy sits on a bridge network with outbound internet access, so it can reach
the real host once this points there. For Codex/OpenAI, use `openai` as the
route tag and point both `sni` and `host_rewrite_literal` at `chatgpt.com`
instead of `api.anthropic.com`.

### 3. Configure Claude Code

Point Claude Code's base URL at the Gate. Put this in your shell profile so
it's there every session, or in the `env` block of your Claude Code
`settings.json` if you'd rather not touch shell startup files:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:10000
```

From here, use `claude` exactly like you always do:

```bash
claude
```

Every Turn now passes through the Gate. Your existing Claude Code
authentication still applies — the Gate never reads it.

### 4. Configure Codex

Codex reads its provider list from a config file, not an environment variable,
so this is a one-time edit instead of an export. Add a provider to
`~/.codex/config.toml` once:

```toml
[model_providers.hamza]
name = "hamza"
base_url = "http://127.0.0.1:10000/backend-api/codex"
wire_api = "responses"
requires_openai_auth = true

[profiles.hamza]
model_provider = "hamza"
```

From here, use `codex` exactly like you always do, just naming the profile:

```bash
codex --profile hamza
```

If you authenticate Codex through ChatGPT rather than an API key, point
`chatgpt_base_url` at the Gate instead:

```bash
codex -c chatgpt_base_url="http://127.0.0.1:10000/backend-api"
```

From here, every Turn your agent sends runs through the Gate on the way to
your real provider. There's nothing separate to demo — the next time a Turn
carries a secret or a registered customer value, watch it get masked in
`hamza_policy_violations_total` at `http://localhost:8080/actuator/prometheus`,
or on the Grafana dashboard at `http://localhost:3000`.

---

## What Hamza does not do

Hamza controls provider egress after an agent assembles a request. It does not
control local file, shell, browser, or database access. An agent can still read
your CSV. It cannot ship it.

The setup above masks secrets and Presidio's approved PII types, with
placeholder identity holding **within each request**. Carrying the same
placeholder across a whole multi-turn task, and pairing each masked request
with a DERIVED Turn audit record, are the two things the signed managed route
adds — they cover complete, supported, unencoded JSON on that route only.

Exact Data Match flags and blocks on the standard route but does not mask
there: it reports how many registered values it saw, not where they sat, and a
value without a reliable span cannot be replaced. Registered-value masking is a
managed-route behavior today.

Streamed oversize, encoded, malformed, and unknown-format requests get
inspected and can Flag or Block, but don't get masked.

OpenAI Responses and Anthropic Messages are the supported wire formats. A new
format needs an adapter that can find and rebuild every provider-visible text
segment.

Three known gaps:

- **Phone numbers do not mask.** Presidio scores `claude-haiku-4-5-20251001` and
  a real phone number at the same 0.4, so no threshold separates them.
- **Bare IPs do not mask.** At 0.6, `127.0.0.1` and `0.0.0.0` in config text
  produced 770 false findings per 10,000 benign turns.
- **One live case never fires EDM** when the customer value arrives by file read.
  Cause under investigation.

## Build and test

```bash
mvn -B clean verify     # 413 tests, spotless, checkstyle, SpotBugs, JaCoCo 80% line / 70% branch
docker build .          # runs mvn verify inside the image
```

Java 25 and Maven 3.9.11 are enforced by `maven-enforcer-plugin`. Compilation
runs with `-Xlint:all -Werror`.

Read [`CONTEXT.md`](./CONTEXT.md) for the domain language. The code is the
source of truth; that document names the file that proves each claim.
