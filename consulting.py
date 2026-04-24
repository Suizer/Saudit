#!/usr/bin/env python3
"""
consulting.py — Unified entry point for the SAUDIT Consulting Suite.

Automatically detects scan scope from the supplied target(s) and selects
the appropriate SAUDIT preset:
  - Single URL / bare domain  → consulting-url-only   (strict scope, no brute)
  - File / multiple targets / CIDR  → consulting-full-scope  (subdomain enum, stealth)

Integrates JsFuzzer and MendixRecon via SAUDIT custom modules.

Usage examples
--------------
  python consulting.py https://target.com
  python consulting.py target.com
  python consulting.py -t targets.txt
  python consulting.py -t 192.168.1.0/24
  python consulting.py https://target.com --scope full
  python consulting.py https://target.com -c consulting.jsfuzzer_path=/opt/JsFuzzer
  python consulting.py https://target.com -o /tmp/reports
  python consulting.py https://target.com --proxy http://127.0.0.1:8080
"""

import re
import sys
import asyncio
import argparse
import ipaddress
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Scope detection
# ──────────────────────────────────────────────────────────────────────────────

def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_file(value: str) -> bool:
    return Path(value).is_file()


def detect_scope(targets: list[str]) -> str:
    """
    Return 'url-only' or 'full-scope' based on the provided targets.

    Rules (in priority order):
    1. Multiple targets → full-scope
    2. Any target is a file → full-scope
    3. Any target is a CIDR or bare IP → full-scope
    4. Single bare domain (no path, no port) → url-only
    5. Single URL with only '/' path → url-only
    6. Anything else → url-only (conservative default)
    """
    if len(targets) > 1:
        return "full-scope"

    target = targets[0]

    if _is_file(target):
        return "full-scope"

    if _is_cidr(target) or _is_ip(target):
        return "full-scope"

    # Strip scheme for analysis
    stripped = re.sub(r"^https?://", "", target)
    host_part = stripped.split("/")[0]      # host[:port]
    path_part = stripped[len(host_part):]   # /rest...

    # Non-trivial path signals a specific endpoint → url-only
    if path_part and path_part.rstrip("/"):
        return "url-only"

    # Bare host or host/ → url-only (no subdomain explosion needed)
    return "url-only"


# ──────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="consulting.py",
        description="SAUDIT Consulting Suite — scope-aware recon with JsFuzzer & MendixRecon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "target",
        nargs="?",
        help="Primary target: URL, domain, IP, or CIDR",
    )
    p.add_argument(
        "-t", "--targets",
        nargs="+",
        metavar="TARGET",
        help="One or more targets (overrides positional target)",
    )
    p.add_argument(
        "--scope",
        choices=["url-only", "full-scope", "auto"],
        default="auto",
        help="Force a specific preset (default: auto-detect)",
    )
    p.add_argument(
        "-o", "--output-dir",
        metavar="DIR",
        help="Directory for SAUDIT scan output",
    )
    p.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP proxy (e.g. http://127.0.0.1:8080)",
    )
    p.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    p.add_argument(
        "-c", "--config",
        nargs="+",
        metavar="KEY=VALUE",
        default=[],
        help="Extra SAUDIT config overrides (e.g. consulting.jsfuzzer_path=/opt/jsfuzzer)",
    )
    p.add_argument(
        "--jsfuzzer",
        metavar="PATH",
        help="Shorthand: path to JsFuzzer tool directory",
    )
    p.add_argument(
        "--mendix-recon",
        metavar="PATH",
        dest="mendix_recon",
        help="Shorthand: path to MendixRecon tool directory",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print resolved config and exit without scanning",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose SAUDIT output",
    )
    return p


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

async def run_scan(targets: list, preset_name: str, extra_config: dict, output_dir: str | None, verbose: bool):
    from saudit.scanner import Scanner
    from saudit.scanner.preset import Preset

    preset_kwargs = {
        "preset": [preset_name],
        "config": extra_config,
    }
    if verbose:
        preset_kwargs["verbosity"] = 1

    preset = Preset(
        *targets,
        **preset_kwargs,
    )
    if output_dir:
        preset.config["output_dir"] = output_dir

    print(f"\n[consulting] Preset  : {preset_name}")
    print(f"[consulting] Targets : {', '.join(targets)}")
    print(f"[consulting] Jitter  : {extra_config.get('consulting', {}).get('request_delay_min', 0):.1f}–"
          f"{extra_config.get('consulting', {}).get('request_delay_max', 0):.1f} s")
    print()

    async with Scanner(preset=preset) as scan:
        async for event in scan.async_start():
            if event.type in ("FINDING", "VULNERABILITY"):
                sev = ""
                if isinstance(event.data, dict):
                    sev = event.data.get("severity", "")
                print(f"  [{event.type}] {sev.upper() + ' ' if sev else ''}{event.data_human}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Resolve targets
    if args.targets:
        targets = args.targets
    elif args.target:
        targets = [args.target]
    else:
        parser.error("Provide a target as a positional argument or via -t/--targets")

    # Auto-detect scope
    if args.scope == "auto":
        scope = detect_scope(targets)
    else:
        scope = args.scope

    preset_name = f"consulting-{scope}"

    # Build extra config dict from -c overrides
    extra_config: dict = {}
    for kv in (args.config or []):
        if "=" not in kv:
            parser.error(f"Config override must be KEY=VALUE, got: {kv!r}")
        key, _, value = kv.partition("=")
        # Support dot-notation: a.b.c=val → {"a": {"b": {"c": val}}}
        _set_nested(extra_config, key.split("."), value)

    # Shorthand flags
    if args.jsfuzzer:
        _set_nested(extra_config, ["consulting", "jsfuzzer_path"], args.jsfuzzer)
    if args.mendix_recon:
        _set_nested(extra_config, ["consulting", "mendix_recon_path"], args.mendix_recon)
    if args.proxy:
        _set_nested(extra_config, ["web", "http_proxy"], args.proxy)
    if args.no_ssl_verify:
        _set_nested(extra_config, ["web", "ssl_verify"], False)

    if args.dry_run:
        import json
        print(f"Preset  : {preset_name}")
        print(f"Targets : {targets}")
        print(f"Config  : {json.dumps(extra_config, indent=2)}")
        return

    try:
        asyncio.run(run_scan(targets, preset_name, extra_config, args.output_dir, args.verbose))
    except KeyboardInterrupt:
        print("\n[consulting] Scan interrupted.")
        sys.exit(0)
    except Exception as e:
        print(f"[consulting] Error: {e}")
        sys.exit(1)


def _set_nested(d: dict, keys: list, value):
    for key in keys[:-1]:
        d = d.setdefault(key, {})
    d[keys[-1]] = value


if __name__ == "__main__":
    main()
