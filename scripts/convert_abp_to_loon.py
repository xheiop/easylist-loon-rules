#!/usr/bin/env python3
"""Convert an ABP network filter list to Loon rule sets."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable


SEPARATOR_REGEX = r"(?:[^A-Za-z0-9_.%-]|$)"
COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#")
NON_BLOCKING_MODIFIERS = {
    "addheader",
    "csp",
    "header",
    "permissions",
    "queryprune",
    "redirect",
    "redirect-rule",
    "removeparam",
    "replace",
    "rewrite",
    "uritransform",
    "urlskip",
}
DOMAIN_PATTERN = re.compile(r"^\|\|([A-Za-z0-9._-]+)\^$")
OPTION_NAME_PATTERN = re.compile(r"^~?([A-Za-z][A-Za-z0-9_-]*)(?:=.*)?$")


@dataclass
class ConversionResult:
    domains: set[str] = field(default_factory=set)
    regexes: set[str] = field(default_factory=set)
    allow_regexes: set[str] = field(default_factory=set)
    skipped: Counter[str] = field(default_factory=Counter)
    approximated_options: Counter[str] = field(default_factory=Counter)
    source_lines: int = 0
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def total_block_rules(self) -> int:
        return len(self.domains) + len(self.regexes)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input-file", type=Path, help="local ABP filter list")
    source.add_argument("--input-url", help="remote ABP filter list URL")
    parser.add_argument(
        "--source-label",
        help="source shown in generated metadata (defaults to the input path or URL)",
    )
    parser.add_argument(
        "--expected-title",
        help="abort unless the ABP metadata contains this exact Title",
    )
    parser.add_argument("--output", type=Path, required=True, help="full Loon rule set")
    parser.add_argument(
        "--domain-output",
        type=Path,
        required=True,
        help="domain-only Loon rule set",
    )
    parser.add_argument(
        "--allow-output",
        type=Path,
        required=True,
        help="unconditional EasyPrivacy exceptions for a preceding DIRECT rule set",
    )
    parser.add_argument("--stats-output", type=Path, required=True)
    parser.add_argument(
        "--min-rules",
        type=int,
        default=10_000,
        help="abort if fewer block rules are generated (default: 10000)",
    )
    return parser.parse_args(argv)


def download_text(url: str, attempts: int = 3) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/plain",
            "Accept-Encoding": "identity",
            "User-Agent": "easyprivacy-loon-sync/1.0",
        },
    )
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            return data.decode("utf-8-sig")
        except (OSError, UnicodeError, urllib.error.URLError) as error:
            last_error = error
            if attempt != attempts:
                time.sleep(attempt * 2)
    raise RuntimeError(f"failed to download {url}: {last_error}") from last_error


def read_source(args: argparse.Namespace) -> tuple[str, str]:
    if args.input_file:
        label = args.source_label or str(args.input_file)
        return args.input_file.read_text(encoding="utf-8-sig"), label
    return download_text(args.input_url), args.source_label or args.input_url


def parse_metadata(lines: Iterable[str]) -> dict[str, str]:
    wanted = {"Title", "Version", "Last modified", "Checksum", "Homepage", "Licence", "License"}
    metadata: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith("! ") or ":" not in line:
            continue
        key, value = line[2:].split(":", 1)
        if key in wanted:
            metadata["Licence" if key == "License" else key] = value.strip()
    return metadata


def split_options(rule: str) -> tuple[str, list[str]]:
    """Split an ABP pattern from its trailing options.

    A dollar sign inside a /regular expression/ is not an option delimiter.
    """

    if rule.startswith("/"):
        closing_slash = find_regex_closing_slash(rule)
        if closing_slash is not None:
            suffix = rule[closing_slash + 1 :]
            if not suffix:
                return rule, []
            if suffix.startswith("$"):
                return rule[: closing_slash + 1], split_option_list(suffix[1:])

    if "$" not in rule:
        return rule, []
    pattern, option_text = rule.rsplit("$", 1)
    options = split_option_list(option_text)
    if not options or any(not OPTION_NAME_PATTERN.match(option) for option in options):
        return rule, []
    return pattern, options


def split_option_list(option_text: str) -> list[str]:
    return [part.strip() for part in option_text.split(",") if part.strip()]


def find_regex_closing_slash(rule: str) -> int | None:
    escaped = False
    in_character_class = False
    last_slash: int | None = None
    for index in range(1, len(rule)):
        character = rule[index]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_character_class = True
        elif character == "]":
            in_character_class = False
        elif character == "/" and not in_character_class:
            last_slash = index
    return last_slash


def without_badfilter(options: list[str]) -> list[str]:
    return [option for option in options if option_name(option) != "badfilter"]


def option_name(option: str) -> str:
    return option.lstrip("~").split("=", 1)[0].lower()


def reconstruct_rule(pattern: str, options: list[str]) -> str:
    return pattern if not options else f"{pattern}${','.join(options)}"


def collect_disabled_rules(lines: Iterable[str]) -> set[str]:
    disabled: set[str] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("!", "[")):
            continue
        exception_prefix = "@@" if line.startswith("@@") else ""
        body = line[2:] if exception_prefix else line
        pattern, options = split_options(body)
        if any(option_name(option) == "badfilter" for option in options):
            disabled.add(exception_prefix + reconstruct_rule(pattern, without_badfilter(options)))
    return disabled


def is_valid_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value or value.startswith(".") or value.endswith("."):
        return False
    labels = value.split(".")
    return all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[A-Za-z0-9-]+", label)
        for label in labels
    )


def domain_rule(pattern: str) -> tuple[str, str] | None:
    match = DOMAIN_PATTERN.fullmatch(pattern)
    if not match:
        return None
    candidate = match.group(1).lower()
    if not is_valid_domain(candidate):
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return "DOMAIN-SUFFIX", candidate
    return "DOMAIN", candidate


def compact_domains(domains: Iterable[str]) -> set[str]:
    """Drop subdomains already covered by a parent DOMAIN-SUFFIX rule."""

    result: set[str] = set()
    for domain in sorted(set(domains), key=lambda item: (item.count("."), item)):
        labels = domain.split(".")
        if any(".".join(labels[index:]) in result for index in range(1, len(labels) - 1)):
            continue
        result.add(domain)
    return result


def raw_regex_to_loon(pattern: str, match_case: bool) -> str | None:
    closing_slash = find_regex_closing_slash(pattern)
    if closing_slash != len(pattern) - 1:
        return None
    expression = pattern[1:closing_slash]
    # A comma separates fields in a Loon rule. Rewriting commas in arbitrary
    # regexes can change quantifiers such as {1,3}, so skip those few rules.
    if not expression or "," in expression or "\n" in expression or "\r" in expression:
        return None
    return expression if match_case else f"(?i){expression}"


def wildcard_pattern_to_loon(pattern: str, match_case: bool) -> str | None:
    if not pattern or "\n" in pattern or "\r" in pattern:
        return None

    domain_anchor = pattern.startswith("||")
    start_anchor = pattern.startswith("|") and not domain_anchor
    end_anchor = pattern.endswith("|") and not pattern.endswith("\\|")

    if domain_anchor:
        pattern = pattern[2:]
    elif start_anchor:
        pattern = pattern[1:]
    if end_anchor:
        pattern = pattern[:-1]
    if not pattern:
        return None

    output: list[str] = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            output.append(".*")
        elif character == "^":
            output.append(SEPARATOR_REGEX)
        elif character == ",":
            output.append(r"\x2C")
        elif character == "\\" and index + 1 < len(pattern):
            index += 1
            output.append(re.escape(pattern[index]))
        else:
            output.append(re.escape(character))
        index += 1

    prefix = ""
    if not match_case:
        prefix += "(?i)"
    if domain_anchor:
        prefix += r"^https?://(?:[^/?#:@]+\.)*"
    elif start_anchor:
        prefix += "^"
    suffix = "$" if end_anchor else ""
    return prefix + "".join(output) + suffix


def to_loon_regex(pattern: str, options: list[str]) -> str | None:
    match_case = any(option_name(option) == "match-case" for option in options)
    if pattern.startswith("/") and find_regex_closing_slash(pattern) == len(pattern) - 1:
        expression = raw_regex_to_loon(pattern, match_case)
    else:
        expression = wildcard_pattern_to_loon(pattern, match_case)
    if expression is None or "," in expression:
        return None
    try:
        re.compile(expression)
    except re.error:
        return None
    return expression


def convert(text: str) -> ConversionResult:
    lines = text.splitlines()
    result = ConversionResult(source_lines=len(lines), metadata=parse_metadata(lines))
    disabled_rules = collect_disabled_rules(lines)
    domain_values: set[str] = set()
    exact_ip_rules: set[str] = set()

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            result.skipped["empty"] += 1
            continue
        if line.startswith(("!", "[")):
            result.skipped["metadata_or_comment"] += 1
            continue
        if any(marker in line for marker in COSMETIC_MARKERS):
            result.skipped["cosmetic"] += 1
            continue

        is_exception = line.startswith("@@")
        body = line[2:] if is_exception else line
        pattern, options = split_options(body)
        canonical = ("@@" if is_exception else "") + reconstruct_rule(pattern, options)
        if canonical in disabled_rules:
            result.skipped["disabled_by_badfilter"] += 1
            continue
        if any(option_name(option) == "badfilter" for option in options):
            result.skipped["badfilter_directive"] += 1
            continue

        names = {option_name(option) for option in options}
        if names & NON_BLOCKING_MODIFIERS:
            result.skipped["non_blocking_modifier"] += 1
            continue

        if is_exception:
            # Scoped/type-specific ABP exceptions would become dangerously broad
            # if used as unconditional DIRECT rules in Loon.
            if options:
                result.skipped["scoped_exception"] += 1
                continue
            expression = to_loon_regex(pattern, options)
            if expression is None:
                result.skipped["unconvertible_exception"] += 1
            else:
                result.allow_regexes.add(expression)
            continue

        for option in options:
            name = option_name(option)
            if name not in {"important", "match-case"}:
                result.approximated_options[name] += 1

        converted_domain = domain_rule(pattern)
        if converted_domain:
            rule_type, value = converted_domain
            if rule_type == "DOMAIN":
                exact_ip_rules.add(f"DOMAIN,{value}")
            else:
                domain_values.add(value)
            continue

        expression = to_loon_regex(pattern, options)
        if expression is None:
            result.skipped["unconvertible_network_rule"] += 1
        else:
            result.regexes.add(expression)

    compacted = compact_domains(domain_values)
    result.domains = {f"DOMAIN-SUFFIX,{domain}" for domain in compacted} | exact_ip_rules
    return result


def header_lines(result: ConversionResult, source: str, kind: str) -> list[str]:
    title = result.metadata.get("Title", "ABP filter list")
    lines = [
        f"# {title} for Loon",
        f"# Variant: {kind}",
        f"# Source: {source}",
    ]
    for key in ("Version", "Last modified", "Checksum", "Licence"):
        if value := result.metadata.get(key):
            lines.append(f"# Upstream {key}: {value}")
    lines.extend(
        [
            "# Generated by scripts/convert_abp_to_loon.py; do not edit manually.",
            "# Select the policy in Loon's [Remote Rule] entry.",
            "",
        ]
    )
    return lines


def render_full(result: ConversionResult, source: str) -> str:
    lines = header_lines(result, source, "full (domain and URL regex)")
    lines.extend(sorted(result.domains))
    if result.domains and result.regexes:
        lines.append("")
    lines.extend(f"URL-REGEX,{expression}" for expression in sorted(result.regexes))
    return "\n".join(lines).rstrip() + "\n"


def render_domains(result: ConversionResult, source: str) -> str:
    lines = header_lines(result, source, "domain-only (faster, lower coverage)")
    lines.extend(sorted(result.domains))
    return "\n".join(lines).rstrip() + "\n"


def render_allow(result: ConversionResult, source: str) -> str:
    lines = header_lines(result, source, "unconditional exceptions (use DIRECT before block)")
    lines.extend(f"URL-REGEX,{expression}" for expression in sorted(result.allow_regexes))
    return "\n".join(lines).rstrip() + "\n"


def stats_document(result: ConversionResult, source: str) -> dict[str, object]:
    return {
        "source": source,
        "upstream": result.metadata,
        "source_lines": result.source_lines,
        "generated": {
            "block_total": result.total_block_rules,
            "domain": len(result.domains),
            "url_regex": len(result.regexes),
            "unconditional_exceptions": len(result.allow_regexes),
        },
        "approximated_abp_options": dict(sorted(result.approximated_options.items())),
        "skipped": dict(sorted(result.skipped.items())),
    }


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(content)
        temporary_path = Path(handle.name)
    temporary_path.replace(path)


def validate_result(result: ConversionResult, minimum: int) -> None:
    if result.total_block_rules < minimum:
        raise RuntimeError(
            f"generated only {result.total_block_rules} block rules; expected at least {minimum}"
        )
    for rule in result.domains:
        if rule.count(",") != 1 or not rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")):
            raise RuntimeError(f"invalid domain rule: {rule}")
    for expression in result.regexes | result.allow_regexes:
        if "," in expression or "\n" in expression or "\r" in expression:
            raise RuntimeError(f"invalid URL-REGEX field: {expression}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    text, source_name = read_source(args)
    if "[Adblock Plus" not in text[:200] or len(text) < 10_000:
        raise RuntimeError("input does not look like a complete Adblock Plus filter list")

    metadata = parse_metadata(text.splitlines())
    if args.expected_title and metadata.get("Title") != args.expected_title:
        raise RuntimeError(
            f"unexpected filter title {metadata.get('Title')!r}; expected {args.expected_title!r}"
        )

    result = convert(text)
    validate_result(result, args.min_rules)
    atomic_write(args.output, render_full(result, source_name))
    atomic_write(args.domain_output, render_domains(result, source_name))
    atomic_write(args.allow_output, render_allow(result, source_name))
    atomic_write(
        args.stats_output,
        json.dumps(stats_document(result, source_name), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
    )
    print(
        f"generated {result.total_block_rules} block rules "
        f"({len(result.domains)} domain, {len(result.regexes)} URL regex) and "
        f"{len(result.allow_regexes)} unconditional exceptions"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
