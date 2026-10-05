#!/usr/bin/env python3
"""Generate the built-in Entra directory role catalogue the simulator serves.

Reads Microsoft's own role reference, which lists every built-in role with its description and
template ID in a single blockquoted table:

    > | [Global Administrator](#global-administrator) | Can manage all aspects... | 62e90394-... |

The template IDs matter: `azuread_directory_role` activates a role by `template_id`, and real
Terraform configurations name these values directly.

Usage:
    git clone --depth 1 https://github.com/MicrosoftDocs/entra-docs
    scripts/generate-directory-roles.py \\
        entra-docs/docs/identity/role-based-access-control/permissions-reference.md \\
        src/graph/directory_roles.json
"""

import json
import re
import sys

# A blockquoted table row: the display name as a markdown link, a description, and a GUID.
ROW = re.compile(
    r"^>\s*\|\s*\[(?P<name>[^\]]+)\]\([^)]*\)\s*\|"
    r"(?P<description>.*?)\|\s*"
    r"(?P<template_id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"\s*\|\s*$"
)


def clean(description):
    """Strip the markdown the description carries for the docs site."""
    # Drop image links, then plain links, keeping their text, then inline markup.
    description = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", description)
    description = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", description)
    description = description.replace("<br/>", " ").replace("<br>", " ")
    description = re.sub(r"[*`]", "", description)
    return " ".join(description.split())


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    source, destination = sys.argv[1], sys.argv[2]
    with open(source, encoding="utf-8") as handle:
        text = handle.read()

    roles = {}
    for line in text.splitlines():
        row = ROW.match(line)
        if not row:
            continue
        # The same role can be listed more than once; the first entry wins.
        roles.setdefault(
            row.group("template_id"),
            {
                "id": row.group("template_id"),
                "displayName": row.group("name").strip(),
                "description": clean(row.group("description")),
            },
        )

    catalogue = sorted(roles.values(), key=lambda role: role["displayName"])
    if len(catalogue) < 50:
        print(
            f"refusing to write a suspiciously small catalogue: {len(catalogue)} roles",
            file=sys.stderr,
        )
        return 1

    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(catalogue, handle, indent=2)
        handle.write("\n")

    print(f"wrote {len(catalogue)} directory role templates to {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
