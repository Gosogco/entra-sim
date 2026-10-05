#!/usr/bin/env python3
"""Generate the Microsoft Graph permission catalogue the simulator serves.

Reads Microsoft's own permissions reference, which records every Graph permission with its
identifier, display text, description and admin-consent requirement in a fixed table layout:

    ### User.Read.All

    | Category | Application | Delegated |
    |--|--|--|
    | Identifier | df021288-... | a154be20-... |
    | DisplayText | Read all users' full profiles | Read all users' full profiles |
    ...

The identifiers matter: Terraform configurations name them directly in
`required_resource_access`, so a simulator that invented them would break real configurations.

Usage:
    git clone --depth 1 https://github.com/microsoftgraph/microsoft-graph-docs-contrib
    scripts/generate-graph-permissions.py \\
        microsoft-graph-docs-contrib/concepts/permissions-reference.md \\
        src/graph/graph_permissions.json
"""

import json
import re
import sys

HEADING = re.compile(r"^### (?P<name>[A-Za-z0-9.\-_]+)\s*$")
ROW = re.compile(r"^\|\s*(?P<field>[A-Za-z]+)\s*\|(?P<rest>.*)\|\s*$")


def cells(rest):
    """Split a table row's body into its Application and Delegated cells."""
    parts = [part.strip() for part in rest.split("|")]
    # Rows carry exactly two value columns; anything else is a layout we do not understand.
    return parts if len(parts) == 2 else None


def parse(text):
    permissions = {}
    current = None

    for line in text.splitlines():
        heading = HEADING.match(line)
        if heading:
            current = heading.group("name")
            permissions[current] = {}
            continue

        if current is None:
            continue

        row = ROW.match(line)
        if not row:
            continue
        values = cells(row.group("rest"))
        if values is None:
            continue
        permissions[current][row.group("field")] = values

    return permissions


def build(permissions):
    """Split the parsed table into app roles and delegated scopes."""
    roles, scopes = [], []

    for name, fields in sorted(permissions.items()):
        identifier = fields.get("Identifier")
        if not identifier:
            continue
        application, delegated = identifier
        display = fields.get("DisplayText", ["", ""])
        description = fields.get("Description", ["", ""])
        consent = fields.get("AdminConsentRequired", ["", ""])

        # A dash means the permission does not exist in that form.
        if application and application != "-":
            roles.append(
                {
                    "id": application,
                    "value": name,
                    "displayName": display[0],
                    "description": description[0],
                    "isEnabled": True,
                    "allowedMemberTypes": ["Application"],
                }
            )
        if delegated and delegated != "-":
            scopes.append(
                {
                    "id": delegated,
                    "value": name,
                    "adminConsentDisplayName": display[1],
                    "adminConsentDescription": description[1],
                    "userConsentDisplayName": display[1],
                    "userConsentDescription": description[1],
                    "isEnabled": True,
                    "type": "Admin" if consent[1] == "Yes" else "User",
                }
            )

    return roles, scopes


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    source, destination = sys.argv[1], sys.argv[2]
    with open(source, encoding="utf-8") as handle:
        permissions = parse(handle.read())

    roles, scopes = build(permissions)
    if len(roles) < 100 or len(scopes) < 100:
        print(
            f"refusing to write a suspiciously small catalogue: "
            f"{len(roles)} roles, {len(scopes)} scopes",
            file=sys.stderr,
        )
        return 1

    # Sorted and newline-terminated so regenerating produces a reviewable diff.
    with open(destination, "w", encoding="utf-8") as handle:
        json.dump({"appRoles": roles, "oauth2PermissionScopes": scopes}, handle, indent=2)
        handle.write("\n")

    print(f"wrote {len(roles)} app roles and {len(scopes)} delegated scopes to {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
