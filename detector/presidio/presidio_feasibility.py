#!/usr/bin/env python3
"""Deterministic fake-data Presidio feasibility evaluation."""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import pathlib
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent
ENDPOINT_HOST = "127.0.0.1"
ENDPOINT_PORT = 3000
# Collection threshold: every candidate threshold must be at or above this value,
# or a Finding that a candidate would admit never reaches the metrics.
MIN_THRESHOLD = 0.35
# The profile default. An entity that cannot qualify at or below this value keeps
# it, so its behaviour is identical to the profile shipped before per-entity
# thresholds existed: no improvement and no regression.
DEFAULT_THRESHOLD = 0.75
# The only two quality failures that mean an entity masks text that is not PII.
# Every other failure means it masks too little, which is never a reason to
# disable an entity that is already enforcing.
SAFETY_FAILURES = ("precision_below_floor", "benign_false_findings_above_floor")
RESPONSE_LIMIT = 1_048_576
BATCH_SIZE = 100


def load_json(name: str) -> dict[str, Any]:
    with (ROOT / name).open(encoding="utf-8") as handle:
        return json.load(handle)


PROFILE = load_json("candidate-profile.json")
CORPUS = load_json("corpus-manifest.json")
ENTITIES = PROFILE["entities"]
FLOORS = PROFILE["quality_floors"]


def luhn_value(prefix: str, serial: int, length: int = 16) -> str:
    body = (prefix + f"{serial:020d}")[: length - 1]
    for digit in range(10):
        candidate = body + str(digit)
        total = 0
        parity = len(candidate) % 2
        for index, character in enumerate(candidate):
            value = int(character)
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        if total % 10 == 0:
            return candidate
    raise AssertionError("unable to generate Luhn value")


def base58check(seed: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    payload = b"\x00" + hashlib.sha256(seed.encode()).digest()[:20]
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    raw = payload + checksum
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    leading = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading + encoded


def iban_value(partition: str, index: int) -> str:
    bank = "TUNE" if partition == "tuning" else "HOLD"
    account = f"{index + (1000 if partition == 'tuning' else 9000):014d}"
    provisional = f"GB00{bank}{account}"
    rearranged = provisional[4:] + provisional[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char
                      for char in rearranged)
    check = 98 - (int(numeric) % 97)
    return f"GB{check:02d}{bank}{account}"


def dea_value(partition: str, index: int) -> str:
    prefix = "AB" if partition == "tuning" else "FT"
    digits = [int(char) for char in f"{index + 101001:06d}"[-6:]]
    check = (sum(digits[0::2]) + 2 * sum(digits[1::2])) % 10
    return prefix + "".join(str(value) for value in digits) + str(check)


def positive_value(entity: str, partition: str, index: int) -> str:
    offset = index + (0 if partition == "tuning" else 100)
    if entity == "CREDIT_CARD":
        raw = luhn_value("4", offset + 10_000)
        value = raw if index % 2 == 0 else " ".join(raw[pos:pos + 4]
                                                     for pos in range(0, 16, 4))
        return value
    if entity == "CRYPTO":
        return base58check(f"{partition}-crypto-{index}")
    if entity == "DATE_TIME":
        months = ["January", "February", "March", "April", "May", "June",
                  "July", "August", "September", "October", "November", "December"]
        return f"{months[offset % 12]} {(offset % 27) + 1}, {2090 + offset // 12}"
    if entity == "EMAIL_ADDRESS":
        return f"fixture-{partition}-{index:03d}@example.com"
    if entity == "IBAN_CODE":
        return iban_value(partition, index)
    if entity == "IP_ADDRESS":
        ranges = ["192.0.2", "198.51.100", "203.0.113"]
        return f"{ranges[offset % 3]}.{(offset % 250) + 1}"
    if entity == "MAC_ADDRESS":
        return f"02:00:5e:{offset // 65536:02x}:{(offset // 256) % 256:02x}:{offset % 256:02x}"
    if entity == "NRP":
        tuning = ["Canadian", "Swedish", "Norwegian", "Danish", "Finnish",
                  "Icelandic", "French", "German", "Spanish", "Italian"]
        holdout = ["Brazilian", "Mexican", "Japanese", "Korean", "Australian",
                   "Irish", "Dutch", "Belgian", "Austrian", "Swiss"]
        values = tuning if partition == "tuning" else holdout
        return values[index % len(values)]
    if entity == "LOCATION":
        tuning = ["Stockholm", "Oslo", "Copenhagen", "Helsinki", "Reykjavik",
                  "Paris", "Berlin", "Madrid", "Rome", "Lisbon"]
        holdout = ["Dublin", "Vienna", "Brussels", "Amsterdam", "Prague",
                   "Warsaw", "Athens", "Zurich", "Edinburgh", "Barcelona"]
        values = tuning if partition == "tuning" else holdout
        return values[index % len(values)]
    if entity == "PERSON":
        tuning = ["Anna Example", "Rene Fixture", "Mira Sample", "Oskar Testman",
                  "Nora Demo", "Leo Placeholder", "Sara Mock", "Elias Synthetic",
                  "Lina Fiction", "Hugo Sandbox"]
        holdout = ["Amelia Testford", "Noah Exampleton", "Sofia Fixtureton",
                   "Lucas Sampleby", "Ella Mockson", "Oliver Demowell",
                   "Freja Testberg", "Milo Fictions", "Alma Sandboxer",
                   "Theo Placeholder"]
        values = tuning if partition == "tuning" else holdout
        return values[index % len(values)]
    if entity == "PHONE_NUMBER":
        area = "202" if partition == "tuning" else "212"
        return f"+1 {area}-555-{100 + index:04d}"
    if entity == "MEDICAL_LICENSE":
        return dea_value(partition, index)
    if entity == "URL":
        return f"https://{partition}-{index:03d}.example.com/help/{index}"
    raise AssertionError(f"unsupported entity: {entity}")


def positive_cases(entity: str, partition: str) -> list[dict[str, Any]]:
    count = CORPUS["partitions"][partition]["positive_occurrences_per_entity"]
    cases = []
    for index in range(count):
        value = positive_value(entity, partition, index)
        # The prefix carries no entity name and no context word. Presidio's context
        # enhancer adds +0.35 when either sits beside the value, which made every
        # positive score as if a helpful word were always present. A Turn that names
        # no helpful word is the case this corpus has to measure.
        prefix = f"case {partition[0]}-{index:03d}: "
        text = prefix + value + " recorded for synthetic evaluation."
        start = len(prefix)
        cases.append({"text": text, "start": start, "end": start + len(value)})
    return cases


def benign_cases(partition: str) -> list[str]:
    """Turns that carry no PII, shaped like the traffic a coding Agent really sends.

    A lower threshold is only safe if precision survives this text, so the benign
    half carries the shapes that a relaxed IP, MAC, phone or URL rule is most
    likely to misread: semantic versions, timestamps, UUIDs, git SHAs, loopback
    and unspecified addresses in config, host:port pairs, stack traces, JSON with
    "url" and "host" keys, colon-separated code identifiers, and Claude model IDs
    (the version-and-date tail of a model ID scores as PHONE_NUMBER at the same
    0.4 a real phone number does). Every template embeds {case} so the two
    partitions stay disjoint.
    """
    count = CORPUS["partitions"][partition]["benign_turns"]
    templates = [
        "control turn {case} reports status ok and queue depth {number}.",
        "build shard {case} compiled module alpha_{number} without warnings.",
        "worker {case} processed batch ref_{number} and returned success.",
        "test case {case} compares expected token_{number} with actual output.",
        "cache segment {case} contains {number} synthetic objects and no user data.",
        "service note {case} uses owner at host notation in documentation.",
        "parser sample {case} rejects 999.999.999.999 as an invalid address.",
        "network sample {case} rejects zz-zz-zz-zz-zz-zz as invalid hardware text.",
        "version sample {case} moved from v1.2.{number} to the next build.",
        "task {case} says retry disabled and fallback path inactive.",
        "release {case} tagged v4.10.{number} and recorded 2026-03-14T08:21:07Z.",
        "record {case} carries trace id 3f2504e0-4f89-41d3-9a0c-0305e82c33{number:02d}.",
        "commit {case} is a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 on the branch.",
        "config {case} binds the listener to 127.0.0.1 and the admin socket to 0.0.0.0.",
        "compose file {case} maps 8080:8080 and 9090:9090 for the local stack.",
        "proxy {case} forwards to localhost:8080 and falls back to localhost:9090.",
        "stack frame {case} at ai.example.masking.Planner.plan(Planner.java:{number}).",
        "{{\"turn\":\"{case}\",\"url\":\"/v1/messages\",\"host\":\"localhost\",\"code\":200}}",
        "logger {case} formats svc:gate:mask:plan:step:v2 as the metric key.",
        "digest {case} pulled sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bb.",
        "token budget {case} used 4096 of 200000 input tokens for this request.",
        "diff {case} changed 3 files with {number} insertions and 12 deletions.",
        "install {case} added 412 packages from registry.npmjs.org in 8.2 seconds.",
        "grep {case} matched src/main/java/example/gate/GateFilter.java:317 twice.",
        "scheduler {case} runs between 00:15:00 and 23:45:00 UTC every 15 minutes.",
        "probe {case} returned HTTP/1.1 204 No Content after {number} milliseconds.",
        "run {case} selected claude-haiku-4-5-20251001 to answer this turn.",
        "{{\"turn\":\"{case}\",\"model\":\"claude-sonnet-4-5-20250929\",\"index\":{number}}}",
        "system prompt {case} pins the assistant to claude-opus-4-1-20250805 for this session.",
    ]
    return [templates[index % len(templates)].format(
        case=f"{partition[0]}b{index:05d}", number=index % 97)
            for index in range(count)]


def request_analysis(text: str | list[str], entities: list[str],
                     threshold: float) -> tuple[Any, float]:
    body = json.dumps({"text": text, "language": "en", "entities": entities,
                       "score_threshold": threshold}, separators=(",", ":")).encode()
    if len(body) > 65_536:
        raise AssertionError("evaluation request exceeds Turn byte bound")
    started = time.perf_counter_ns()
    connection = http.client.HTTPConnection(ENDPOINT_HOST, ENDPOINT_PORT, timeout=0.9)
    try:
        connection.request("POST", "/analyze", body=body,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(RESPONSE_LIMIT + 1)
    finally:
        connection.close()
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if elapsed_ms > 1_000:
        raise AssertionError("shared detector deadline exceeded")
    if response.status != 200:
        raise AssertionError(f"analyzer returned status {response.status}")
    if len(raw) > RESPONSE_LIMIT:
        raise AssertionError("analyzer response limit exceeded")
    return json.loads(raw), elapsed_ms


def collect_partition(partition: str, threshold: float) -> dict[str, Any]:
    collected: dict[str, Any] = {"positive": {}, "latency": {}, "benign": []}
    for entity in ENTITIES:
        entity_results = []
        latencies = []
        for case in positive_cases(entity, partition):
            results, elapsed = request_analysis(case["text"], [entity], threshold)
            entity_results.append((case, results))
            latencies.append(elapsed)
        collected["positive"][entity] = entity_results
        collected["latency"][entity] = latencies
    benign = benign_cases(partition)
    for start in range(0, len(benign), BATCH_SIZE):
        batch = benign[start:start + BATCH_SIZE]
        results, _ = request_analysis(batch, ENTITIES, threshold)
        if len(results) != len(batch):
            raise AssertionError("incomplete benign batch response")
        collected["benign"].extend(results)
    if len(collected["benign"]) != len(benign):
        raise AssertionError("incomplete benign partition")
    return collected


def percentile95(values: list[float]) -> float:
    ordered = sorted(values)
    position = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[position]


def metrics(entity: str, collected: dict[str, Any], threshold: float,
            benign_count: int) -> dict[str, Any]:
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    positive_findings = 0
    for case, raw_results in collected["positive"][entity]:
        results = [result for result in raw_results
                   if result["entity_type"] == entity and result["score"] >= threshold]
        exact = [result for result in results
                 if result["start"] == case["start"] and result["end"] == case["end"]]
        positive_findings += len(results)
        if exact:
            true_positives += 1
            false_positives += len(results) - 1
        else:
            false_negatives += 1
            false_positives += len(results)
    benign_false = sum(
        1 for turn in collected["benign"] for result in turn
        if result["entity_type"] == entity and result["score"] >= threshold)
    false_positives += benign_false
    precision = (true_positives / (true_positives + false_positives)
                 if true_positives + false_positives else 0.0)
    recall = (true_positives / (true_positives + false_negatives)
              if true_positives + false_negatives else 0.0)
    f2 = (5 * precision * recall / (4 * precision + recall)
          if precision and recall else 0.0)
    exact_span = true_positives / positive_findings if positive_findings else 0.0
    return {
        # Every Finding the entity produced at this threshold. Zero means it masked
        # nothing at all, which makes precision an undefined 0/0 rather than a
        # measurement that the entity masks text which is not PII.
        "findings": positive_findings + benign_false,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f2": round(f2, 4),
        "exact_span_reliability": round(exact_span, 4),
        "benign_false_findings": benign_false,
        "benign_false_findings_per_10000_turns": round(
            benign_false * 10_000 / benign_count, 4),
        "p95_ms": round(percentile95(collected["latency"][entity]), 3),
        "positive_turns": len(collected["positive"][entity]),
        "benign_turns": benign_count,
        "complete": True,
    }


def quality_failures(result: dict[str, Any]) -> list[str]:
    failures = []
    for metric in ["precision", "recall", "f2", "exact_span_reliability"]:
        if result[metric] < FLOORS[metric]:
            failures.append(f"{metric}_below_floor")
    if (result["benign_false_findings_per_10000_turns"]
            > FLOORS["benign_false_findings_per_10000_turns"]):
        failures.append("benign_false_findings_above_floor")
    if result["p95_ms"] > FLOORS["p95_ms"]:
        failures.append("p95_above_floor")
    if not result["complete"]:
        failures.append("incomplete_calls")
    return failures


def assert_disjoint() -> None:
    tuning = set(benign_cases("tuning"))
    holdout = set(benign_cases("holdout"))
    for entity in ENTITIES:
        tuning.update(case["text"] for case in positive_cases(entity, "tuning"))
        holdout.update(case["text"] for case in positive_cases(entity, "holdout"))
    if tuning & holdout:
        raise AssertionError("tuning and holdout corpora overlap")


def unsafe_failures(result: dict[str, Any]) -> list[str]:
    """The failures that mean an entity masks text which is not PII.

    Only these may disable an entity that already enforces. A recall, f2 or
    exact-span failure means the entity misses PII, which is the defect this
    corpus exists to expose, never a reason to stop enforcing. An entity that
    produced no Finding at all masked nothing, so its 0/0 precision is undefined
    rather than evidence of over-masking.
    """
    failures = [failure for failure in quality_failures(result)
                if failure in SAFETY_FAILURES]
    if result["findings"] == 0:
        failures = [failure for failure in failures
                    if failure != "precision_below_floor"]
    return failures


def select_thresholds(tuning: dict[str, Any]) -> dict[str, float]:
    """One threshold per entity: the highest candidate that clears every floor.

    The search stops at DEFAULT_THRESHOLD. An entity that qualifies nowhere at or
    below it keeps that default, so it behaves exactly as it does today. Choosing
    a threshold weighs the full floor set, because an entity only earns a lower
    threshold by meeting every floor there.
    """
    benign_count = CORPUS["partitions"]["tuning"]["benign_turns"]
    candidates = sorted(threshold for threshold in PROFILE["thresholds"]
                        if MIN_THRESHOLD <= threshold <= DEFAULT_THRESHOLD)
    selected = {}
    for entity in ENTITIES:
        selected[entity] = DEFAULT_THRESHOLD
        for threshold in reversed(candidates):
            if not quality_failures(metrics(entity, tuning, threshold, benign_count)):
                selected[entity] = threshold
                break
    return selected


def main() -> None:
    assert_disjoint()
    request_analysis("warmup synthetic control turn", ENTITIES, MIN_THRESHOLD)
    counts = CORPUS["partitions"]
    tuning = collect_partition("tuning", MIN_THRESHOLD)
    thresholds = select_thresholds(tuning)
    holdout = collect_partition("holdout", MIN_THRESHOLD)
    tuning_count = counts["tuning"]["benign_turns"]
    holdout_count = counts["holdout"]["benign_turns"]

    # A threshold below the default is only kept when holdout confirms it. An
    # entity that tuning promoted but holdout does not support falls back to the
    # default, exactly like an entity that never qualified.
    for entity in ENTITIES:
        threshold = thresholds[entity]
        if threshold < DEFAULT_THRESHOLD and quality_failures(
                metrics(entity, holdout, threshold, holdout_count)):
            thresholds[entity] = DEFAULT_THRESHOLD

    holdout_metrics = {entity: metrics(entity, holdout, thresholds[entity], holdout_count)
                       for entity in ENTITIES}
    approved = []
    rejected = []
    gaps = []
    for entity in ENTITIES:
        reasons = quality_failures(holdout_metrics[entity])
        if quality_failures(metrics(entity, tuning, thresholds[entity], tuning_count)):
            reasons.insert(0, "tuning_quality_floor_not_met")
        unsafe = unsafe_failures(holdout_metrics[entity])
        if unsafe:
            rejected.append({"entity": entity, "reasons": reasons})
        else:
            approved.append(entity)
            if reasons:
                gaps.append({"entity": entity, "reasons": reasons})
    report = {
        "schema": "hamza-presidio-feasibility-report/v1",
        "profile_id": PROFILE["profile_id"],
        "profile_version": PROFILE["version"],
        "image": PROFILE["image"],
        # The profile default. Per-entity choices live in entity_thresholds, and
        # an entity absent from that map enforces at this value.
        "selected_threshold": DEFAULT_THRESHOLD,
        "entity_thresholds": thresholds,
        "evaluated_entities": ENTITIES,
        "corpus_counts": {
            "tuning_positive_occurrences_per_entity":
                counts["tuning"]["positive_occurrences_per_entity"],
            "tuning_benign_turns": tuning_count,
            "holdout_positive_occurrences_per_entity":
                counts["holdout"]["positive_occurrences_per_entity"],
            "holdout_benign_turns": holdout_count,
            "partitions_disjoint": True,
        },
        "approved_entities": approved,
        "rejected_entities": rejected,
        # An approved entity that misses a floor it is not disabled for. These are
        # the entities this corpus could not safely improve; they keep the default
        # and behave as they did before.
        "quality_gaps": gaps,
        "holdout_metrics": holdout_metrics,
        "all_calls_complete": True,
        "content_free": True,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
