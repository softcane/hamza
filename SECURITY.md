# Security policy

Hamza sits on the path between a coding agent and a model provider. A defect
here can release bytes that were supposed to be masked, so please report
suspected vulnerabilities privately rather than opening a public issue.

## Reporting

Use GitHub's [private vulnerability
reporting](https://github.com/softcane/hamza/security/advisories/new) on this
repository. Include the wire format (OpenAI Responses or Anthropic Messages), a
minimal request body that reproduces the behavior, and what you expected the
Gate to do.

Please do not include real secrets or real personal data in a report. Every
fixture in this repository is fake, and a report can be too.

## What counts

The behavior worth reporting is anything that gets a detectable value past the
Gate, or that turns a content-free record into one that retains content:

- a supported, complete managed Turn that egresses a value the detectors should
  have masked
- a rebuilt body that leaves residue the final rescan does not catch
- provider authentication being read, logged, or mutated
- request content, matched values, spans, or placeholder mappings appearing in
  records, logs, or metrics
- a failure path that releases bytes instead of failing closed

## What does not

These are documented limits, not vulnerabilities. They are described in the
README:

- streamed oversize, encoded, malformed, and unknown-format requests are
  inspected but not masked
- phone numbers and bare IP addresses do not mask, by decision — no threshold
  separates them from benign text at an acceptable false-positive rate
- person names, locations, dates, nationality, religion, and political
  affiliation are deliberately not enforced
- Hamza does not control local file, shell, browser, or database access

## Supported versions

This project is pre-1.0. Fixes land on `main`; there are no backport branches.
