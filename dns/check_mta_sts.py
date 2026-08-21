import argparse
import hashlib
import http.client
import re
import sys
import urllib.request
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

REPO = Path(__file__).resolve().parent.parent
ZONES = REPO / "dns" / "zones"
GROUP_VARS = "mail/group_vars/mail/main.yml"
TEMPLATE = "mail/roles/mta_sts/templates/mta-sts.txt.j2"
ID = re.compile(r"\bid=([A-Za-z0-9]{1,32})\b")
TIMEOUT = 15


# RFC 8461 section 3.3 forbids senders from following redirects to the policy,
# so a redirect has to fail here rather than resolve to a working policy.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def entries(record):
    return record if isinstance(record, list) else [record]


def values_of(entry):
    return [entry["value"]] if "value" in entry else entry.get("values", [])


def declared_id(record):
    for entry in entries(record):
        if entry.get("type") != "TXT":
            continue
        for value in values_of(entry):
            match = ID.search(value)
            if match:
                return match.group(1)
    return None


def declared_mx(record):
    hosts = []
    for entry in entries(record):
        if entry.get("type") != "MX":
            continue
        for value in values_of(entry):
            exchange = value["exchange"].rstrip(".").lower()
            if exchange:
                hosts.append(exchange)
    return hosts


def policy_id(policy):
    return hashlib.sha256(policy.encode()).hexdigest()[:16]


# Ansible's template module keeps the trailing newline, and the hash the id is
# derived from depends on it.
def render_policy(variables):
    env = Environment(
        keep_trailing_newline=True, trim_blocks=True, undefined=StrictUndefined
    )
    policy = env.from_string((REPO / TEMPLATE).read_text()).render(variables)
    return policy_id(policy), policy


def fetch_policy(url):
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(url, timeout=TIMEOUT) as response:
        policy = response.read().decode()
    return policy_id(policy), policy


def policy_mx(policy):
    hosts = []
    for line in policy.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "mx":
            hosts.append(value.strip().rstrip(".").lower())
    return hosts


# RFC 8461 section 4.1 only allows a wildcard in the leftmost label of an mx entry.
def covered(host, patterns):
    return any(
        pattern == host
        or (pattern.startswith("*.") and host.partition(".")[2] == pattern[2:])
        for pattern in patterns
    )


def listed(hosts):
    return ", ".join(hosts) if hosts else "nothing"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("rendered", "deployed"),
        help="compare the _mta-sts id against the policy this repo renders, or "
        "against the policy the mail host currently serves",
    )
    mode = parser.parse_args().mode

    matched = []
    failures = []
    seen = set()

    variables = yaml.safe_load((REPO / GROUP_VARS).read_text())
    domains = set(variables.get("mail_domains") or [])
    reference = render_policy(variables) if mode == "rendered" else None

    for path in sorted(ZONES.glob("*.yaml")):
        zone = yaml.safe_load(path.read_text())
        record = zone.get("_mta-sts")
        host = zone.get("mta-sts")

        if record is None and host is None:
            continue

        domain = path.stem
        source = f"dns/zones/{path.name}"
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        seen.add(domain)

        if record is None:
            failures.append(
                f"{domain}: {source} has an mta-sts host but no _mta-sts TXT "
                f"record, so no sender will ever fetch the policy."
            )
            continue

        if host is None:
            failures.append(
                f"{domain}: {source} declares _mta-sts but has no mta-sts host "
                f"record to serve {url} from."
            )
            continue

        if domain not in domains:
            failures.append(
                f"{domain}: {source} publishes an MTA-STS policy but "
                f"{GROUP_VARS} does not list it in mail_domains, so the mail "
                f"host serves no policy for it."
            )
            continue

        if mode == "rendered":
            expected, policy = reference
            label = f"{TEMPLATE} rendered from {GROUP_VARS}"
            hint = f"Set id={expected} in {source} in this change."
        else:
            try:
                expected, policy = fetch_policy(url)
            except (OSError, http.client.HTTPException, UnicodeDecodeError) as error:
                failures.append(f"{domain}: cannot fetch {url}: {error}")
                continue
            label = url
            hint = (
                "Run the mail playbook so the served policy catches up, or "
                "correct the _mta-sts record."
            )

        declared = declared_id(record)

        if declared == expected:
            matched.append(f"{domain}: id={declared} matches {label}")
        else:
            failures.append(
                f"{domain}: {source} declares "
                f"{f'id={declared}' if declared else 'no id'} but {label} hashes "
                f"to id={expected}. {hint}"
            )

        patterns = policy_mx(policy)
        exchanges = declared_mx(zone.get("", []))
        uncovered = [mx for mx in exchanges if not covered(mx, patterns)]

        if not exchanges:
            failures.append(
                f"{domain}: {source} publishes an MTA-STS policy but has no "
                f"deliverable MX record."
            )
        elif uncovered:
            failures.append(
                f"{domain}: {label} lists mx={listed(patterns)}, which does not "
                f"cover {listed(uncovered)} from the {source} MX record. "
                f"Senders in enforce mode will refuse delivery."
            )
        else:
            matched.append(
                f"{domain}: policy mx={listed(patterns)} covers the MX record"
            )

    for domain in sorted(domains - seen):
        failures.append(
            f"{domain}: {GROUP_VARS} lists it in mail_domains but no zone in "
            f"dns/zones declares an MTA-STS policy for it."
        )

    for line in matched:
        print(line)
    for line in failures:
        print(line, file=sys.stderr)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
