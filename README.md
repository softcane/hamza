# Hamza

![Hamza masking sensitive data before it reaches an AI service](assets/hamza-undercover-proxy.png)

*The name Hamza is inspired by the undercover operative in
[*Dhurandhar*](https://www.netflix.com/tudum/articles/dhurandhar-release-date-news).*

Hamza is a proxy for Claude Code and Codex. It masks detected secrets and
approved types of personal data before sending prompts to Anthropic or OpenAI.

https://github.com/user-attachments/assets/be336248-ba3f-4597-a05c-fb1af8b3124e

An agent debugging an import job may read a CSV, an `.env` file, and application
logs. That context can contain customer data and credentials. Hamza masks
detected values while leaving the rest of the prompt intact:

```text
Before: patient=priya.fixture@example.com  key=AKIAABCDEFGHIJKLMNOP
After:  patient=<EMAIL_482191>             key=<SECRET_730044>
```

The same value gets the same placeholder within a request. This lets the model
follow references without receiving the original value.

## Why this is an organization problem

Existing security tools may not see the final request assembled by a coding
agent.

| Control | What it sees | What it can miss |
|---|---|---|
| Git secret scanning | Committed files | A key read from `.env` but never committed |
| Endpoint DLP | Files, email, and removable storage | Data inside an allowed HTTPS request |
| Web security tools | Browser traffic | A CLI process calling an approved API |
| Code review | Source-code changes | Logs and files added to a prompt |

A developer may ask an agent to debug an import job without knowing which files
the agent will read. Customer records or credentials can then leave the network
inside a normal request to an approved AI service.

This creates work for security and compliance teams. They may need to rotate a
credential, investigate which records left the network, or change the contract
with the AI vendor. Hamza reduces that exposure by masking detected values
before the request leaves.

Hamza does not replace access controls, retention rules, or legal agreements.

## How it works

```mermaid
flowchart LR
    A["Claude Code or Codex"] --> B["Hamza proxy"]
    B --> C["Find secrets and personal data"]
    C --> D["Apply the configured action"]
    D -->|"mask"| E["Replace the detected value"]
    D -->|"allow"| F["Anthropic or OpenAI"]
    D -->|"block"| G["Stop the request"]
    E --> F
```

1. Hamza inspects supported request bodies from Claude Code or Codex.
2. It finds the text sent to the AI service.
3. The secret scanner, registered-value detector, and Presidio inspect that
   text.
4. Depending on the rule, Hamza records, masks, or blocks the finding.
5. For masking rules, it replaces the detected value with a placeholder such as
   `<SECRET_1>` or `<EMAIL_1>`.

Hamza also writes an audit record with the action, detector, and byte counts.
The record contains no prompt text or matched values.

## What Hamza detects

| Detector | Finds |
|---|---|
| Secret scanner | Cloud, source-control, package-registry, and SaaS credentials |
| Presidio | Email, phone, payment-card, IP, and other approved data types |

You can also register customer values that Hamza should recognize.

The full Presidio entity list and thresholds are in
[`detector/presidio/approved-profile.json`](./detector/presidio/approved-profile.json).

## Run it

You need Docker Compose.

```bash
HAMZA_POSTURE=MASK docker compose up -d --build
```

The first start may take a minute while Presidio loads.

### Claude Code

Set the Anthropic base URL:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:10000
claude
```

Add the export to your shell profile if you want to keep it across sessions.
Claude Code also accepts `ANTHROPIC_BASE_URL` in the `env` section of
`settings.json`.

### Codex

Add this to `~/.codex/config.toml`:

```toml
[model_providers.hamza]
name = "hamza"
base_url = "http://127.0.0.1:10000/backend-api/codex"
wire_api = "responses"
requires_openai_auth = true

[profiles.hamza]
model_provider = "hamza"
```

Then start Codex with the profile:

```bash
codex --profile hamza
```

## Services

| Address | Service |
|---|---|
| `http://127.0.0.1:10000` | Proxy used by Claude Code and Codex |
| `http://127.0.0.1:3000` | Grafana dashboard |
| `http://127.0.0.1:8080/actuator/prometheus` | Prometheus metrics |

Presidio runs inside the Docker network and has no host port.

To disable Presidio:

```bash
HAMZA_PRESIDIO_ENABLED=false \
  HAMZA_POSTURE=MASK \
  docker compose up -d --build --scale presidio=0
```

## Build and test

Hamza requires Java 25 and Maven 3.9.11.

```bash
mvn -B clean verify
docker build .
```

See [`CONTEXT.md`](./CONTEXT.md) for the domain model and
[`AGENTS.md`](./AGENTS.md) for the complete test suite.
