# Hamza language

Hamza is an Egress Gate for CLI coding Agents. Use these terms in code, tests,
Records, operator messages, and commit messages.

**The code is the source of truth.** Where a term below names an enum, a
constant, or a default, the cited file defines it. If they disagree, the code is
right and this glossary is a bug.

## Core terms

**Gate**: The checkpoint between an Agent and a model Provider. The Gate inspects
request bodies before Provider Egress. It does not control local Agent access.

**Agent**: A supported CLI coding agent, such as Codex CLI or Claude Code.

**Provider**: The remote model service that receives an Agent Turn.

**Adapter**: Provider-specific code that parses and rebuilds a supported wire
format. OpenAI Responses and Anthropic Messages are the supported formats
(`adapter/OpenAiResponsesAdapter.java`, `adapter/AnthropicMessagesAdapter.java`).

**Turn**: One request and response exchange. A managed mask operation accounts
for its original and rebuilt requests as separate Turns.

**Egress**: Request bytes leaving the company boundary for a Provider.

**Finding**: A content-free detector result. A Finding identifies the detector,
rule, Action, and reliable span state. It does not retain matched content.

**Action**: The Gate response to a Finding. The Actions are **Flag**, **Mask**,
and **Block** (`policy/Action.java`), resolved in the order `Block > Mask > Flag`
(`policy/PolicyEngine.java`, `severity(Action)`).

**Posture**: The configured default Action for a route or rule. A rule with no
explicit Action falls back to Posture — which means a rule missing from the
action map silently observes instead of enforcing.

**Record**: A content-free account of a Turn. Records may retain byte counts,
detector evidence, Actions, and causal links. They must not retain request
content, matched values, spans, scores, placeholders, mappings, or Provider
authentication.

## Mask and Continue terms

**Mask**: Replace one detected value at a reliable exact span with a safe
placeholder before Provider Egress. Mask preserves the surrounding request.

**Mask Scope**: One managed Agent task in which equal source values reuse equal
placeholders. A scope ends at task completion, cancellation, restart, or 15
minutes (`masking/MaskScopeStore.java`, `DEFAULT_TTL` — also the hard ceiling).

**Placeholder**: Harmless typed text such as `<EMAIL_1>` or `<SECRET_1>`. The
families are `SECRET`, `ACCOUNT`, `EMAIL`, `PHONE`, `PERSON`, `LOCATION`, `IP`,
and `PII` (`masking/PlaceholderFamily.java`). A placeholder stays stable inside
one Mask Scope, does not preserve source formatting, and cannot authenticate or
recover the source value. Different Mask Scopes must not share linkable
placeholders.

**SOURCE Turn**: The original managed request. The Gate inspects and records it
but withholds it when masking occurs.

**DERIVED Turn**: The complete request rebuilt with placeholders. It has separate
byte accounting and a linked Record. The Gate releases it only after every
required detector completes a clean final scan.

**Detection Run**: A content-free account of one detector version, status,
coverage, duration, and Finding count for a SOURCE or DERIVED Turn.

**Exact Data Match (EDM)**: Registry-backed detection of registered customer
values. On the managed route an EDM hit always masks, whatever the rule's
standard-route Action says.

**Safe failure**: Withhold the managed Turn and return Block with Coach when the
Gate cannot prove a complete safe rewrite. Examples include malformed JSON,
incomplete detector work, unreliable spans, failed serialization, or a dirty
final scan.

**Coach**: The operator-facing message returned with a Block. It names a rule
class and a safe next action without repeating matched content.

## Route boundary

The Mask-and-Continue claim covers complete, supported, unencoded JSON on the
managed route. A request is managed when it carries signed `x-hamza-*` metadata
(`extproc/RequestHeaderView.java`); everything else takes the standard route.

Streamed oversize, encoded, malformed, and unknown-format requests do not receive
the Mask-and-Continue claim. The standard route keeps its existing local
inspection behavior and may Flag or Block, but it does not promise stable
placeholders, a DERIVED Turn, or Mask and Continue.

## Detectors

Secret detection and Exact Data Match are always registered
(`masking/MaskDetectionService.java`). Presidio is disabled by default and is
registered only once an operator points it at the pinned in-boundary Analyzer
(`config/PresidioProperties.java`). It runs inside the trust boundary with no
external network access.

Only entities in the approved profile may enforce. The profile is a file path
set by `hamza.presidio.approved-profile` (default
`/opt/hamza/presidio/approved-profile.json`; the repository copy lives at
`detector/presidio/approved-profile.json`). The person-name entity is
deliberately excluded: it did not meet the quality floor, so Presidio is never
asked to look for it and a personal name is expected to reach the Provider
unmasked.

Presidio shares a per-Turn deadline and never retries (200 ms connect, 900 ms
service — `presidio/PresidioClient.java`). A large body can exhaust that deadline,
which marks the run incomplete and fails the Turn closed with a Block. Blocking
on an unfinished required scan is the designed behavior, never a silent pass.
