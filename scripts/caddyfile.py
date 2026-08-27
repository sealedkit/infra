import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

REPO = Path(__file__).resolve().parent.parent
ANSIBLE = REPO / "ansible"
TEMPLATES = ANSIBLE / "templates"
CADDY_ROLE = ANSIBLE / "roles" / "caddy"
GROUPS = ("leaf", "mail")

PINNED = re.compile(r"^\s*name: caddy=(\S+)\s*$", re.MULTILINE)
UNRESOLVED = "{{"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    return 2


def load(path):
    return yaml.safe_load(path.read_text()) or {}


def pinned_version():
    match = PINNED.search((CADDY_ROLE / "tasks" / "main.yml").read_text())
    if not match:
        raise SystemExit(fail("roles/caddy no longer pins a caddy version to install."))
    return match.group(1)


def caddy(*arguments):
    return subprocess.run(
        ["caddy", *arguments], capture_output=True, text=True, check=False
    )


def installed_version():
    return caddy("version").stdout.split()[0].lstrip("v")


# Role vars outrank group_vars in Ansible, so they are merged last.
def variables(group):
    merged = load(ANSIBLE / "group_vars" / group / "main.yml")
    for path in sorted((CADDY_ROLE / "vars" / "main").glob("*.yml")):
        merged.update(load(path))
    return merged


def render(environment, group):
    values = variables(group)
    if "caddy_caddyfile" not in values:
        raise SystemExit(
            fail(f"group_vars/{group} does not name a Caddyfile template.")
        )
    return values["caddy_caddyfile"], environment.get_template(
        values["caddy_caddyfile"]
    ).render(values)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--print-version",
        action="store_true",
        help="print the caddy version the role installs and exit",
    )
    if parser.parse_args().print_version:
        print(pinned_version())
        return 0

    if shutil.which("caddy") is None:
        return fail(
            f"caddy is not on PATH. Install {pinned_version()} from "
            "https://github.com/caddyserver/caddy/releases to validate the templates."
        )

    pinned, installed = pinned_version(), installed_version()
    if installed != pinned:
        print(f"validating with caddy {installed}, the role deploys {pinned}")

    environment = Environment(
        loader=FileSystemLoader(TEMPLATES),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )

    with tempfile.TemporaryDirectory() as directory:
        for group in GROUPS:
            try:
                name, config = render(environment, group)
            except TemplateError as error:
                return fail(f"{group}: {error}")
            if UNRESOLVED in config:
                return fail(
                    f"{name} still holds {UNRESOLVED} after rendering. A variable it "
                    "reads is itself a template, which this script does not expand."
                )
            path = Path(directory) / f"{group}.Caddyfile"
            path.write_text(config)
            formatted = caddy("fmt", "--diff", str(path))
            if formatted.returncode:
                return fail(
                    f"{name} renders output that caddy fmt would rewrite. The diff "
                    f"below is the rendered file:\n{formatted.stdout.strip()}"
                )
            validated = caddy(
                "validate", "--adapter", "caddyfile", "--config", str(path)
            )
            if validated.returncode:
                return fail(f"{name} does not validate:\n{validated.stderr.strip()}")
            print(f"{name} is formatted and validates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
