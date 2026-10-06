#!/usr/bin/env python3
"""Generate the per-endpoint permission requirements the simulator enforces.

Microsoft publishes the required permissions for every Graph endpoint as a generated include
file, one per operation, each containing a table like:

    |Permission type|Least privileged permissions|Higher privileged permissions|
    |:---|:---|:---|
    |Delegated (work or school account)|Application.ReadWrite.All|Directory.ReadWrite.All|
    |Application|Application.ReadWrite.OwnedBy|Application.ReadWrite.All, Directory.ReadWrite.All|

Taking the requirements from there rather than writing them by hand means the simulator refuses
and permits the same calls the real service does.

A cell can express both alternatives and conjunctions:

    AppRoleAssignment.ReadWrite.All and Application.Read.All|..., Application.ReadWrite.All

which reads as "(AppRoleAssignment.ReadWrite.All AND Application.Read.All) OR
Application.ReadWrite.All". The output therefore models each requirement as a list of
alternatives, each alternative a list of permissions that must all be held.

The route-to-document mapping below is the only hand-written part, and is what to check when a
route's enforcement looks wrong.

Most operations have a generated include file. Some older ones keep the same table inline on
their API reference page instead, in one of two further shapes, so both locations are read.

Usage:
    git clone --depth 1 https://github.com/microsoftgraph/microsoft-graph-docs-contrib
    scripts/generate-permission-requirements.py \\
        microsoft-graph-docs-contrib/api-reference/v1.0 \\
        src/auth/permission_requirements.json
"""

import json
import os
import re
import sys

# Which published operation governs each route the simulator serves. Paths are the matched
# axum route patterns, without the version prefix.
ROUTES = [
    # /me reads the signed-in user, so it carries the same requirement as reading a user.
    ("GET", "/me", "user-get"),
    ("GET", "/users", "user-list"),
    ("POST", "/users", "user-post-users"),
    ("GET", "/users/{id}", "user-get"),
    ("PATCH", "/users/{id}", "user-update"),
    ("PUT", "/users/{id}", "user-update"),
    ("DELETE", "/users/{id}", "user-delete"),
    ("GET", "/users/{id}/memberOf", "user-list-memberof"),
    ("GET", "/users/{id}/appRoleAssignments", "user-list-approleassignments"),
    ("POST", "/users/{id}/appRoleAssignments", "user-post-approleassignments"),
    ("DELETE", "/users/{id}/appRoleAssignments/{assignment_id}", "user-delete-approleassignments"),

    ("GET", "/groups", "group-list"),
    ("POST", "/groups", "group-post-groups"),
    ("GET", "/groups/{id}", "group-get"),
    ("PATCH", "/groups/{id}", "group-update"),
    ("PUT", "/groups/{id}", "group-update"),
    ("DELETE", "/groups/{id}", "group-delete"),
    ("GET", "/groups/{id}/members", "group-list-members"),
    ("GET", "/groups/{id}/members/$ref", "group-list-members"),
    ("POST", "/groups/{id}/members/$ref", "group-post-members"),
    ("DELETE", "/groups/{id}/members/{member_id}/$ref", "group-delete-members"),
    ("GET", "/groups/{id}/owners", "group-list-owners"),
    ("GET", "/groups/{id}/owners/$ref", "group-list-owners"),
    ("POST", "/groups/{id}/owners/$ref", "group-post-owners"),
    ("DELETE", "/groups/{id}/owners/{owner_id}/$ref", "group-delete-owners"),
    ("GET", "/groups/{id}/transitiveMembers", "group-list-transitivemembers"),
    ("GET", "/groups/{id}/memberOf", "group-list-memberof"),
    ("GET", "/groups/{id}/appRoleAssignments", "group-list-approleassignments"),

    ("GET", "/applications", "application-list"),
    ("POST", "/applications", "application-post-applications"),
    ("GET", "/applications/{id}", "application-get"),
    ("PATCH", "/applications/{id}", "application-update"),
    ("PUT", "/applications/{id}", "application-update"),
    ("DELETE", "/applications/{id}", "application-delete"),
    ("POST", "/applications/{id}/addPassword", "application-addpassword"),
    ("POST", "/applications/{id}/removePassword", "application-removepassword"),
    ("POST", "/applications/{id}/addKey", "application-addkey"),
    ("POST", "/applications/{id}/removeKey", "application-removekey"),
    ("GET", "/applications/{id}/owners", "application-list-owners"),
    ("POST", "/applications/{id}/owners/$ref", "application-post-owners"),
    ("DELETE", "/applications/{id}/owners/{owner_id}/$ref", "application-delete-owners"),
    (
        "GET",
        "/applications/{id}/federatedIdentityCredentials",
        "federatedidentitycredential-list",
    ),
    (
        "POST",
        "/applications/{id}/federatedIdentityCredentials",
        "federatedidentitycredential-post",
    ),
    (
        "GET",
        "/applications/{id}/federatedIdentityCredentials/{credential_id}",
        "federatedidentitycredential-get",
    ),
    (
        "DELETE",
        "/applications/{id}/federatedIdentityCredentials/{credential_id}",
        "federatedidentitycredential-delete",
    ),

    ("GET", "/servicePrincipals", "serviceprincipal-list"),
    ("POST", "/servicePrincipals", "serviceprincipal-post-serviceprincipals"),
    ("GET", "/servicePrincipals/{id}", "serviceprincipal-get"),
    ("PATCH", "/servicePrincipals/{id}", "serviceprincipal-update"),
    ("PUT", "/servicePrincipals/{id}", "serviceprincipal-update"),
    ("DELETE", "/servicePrincipals/{id}", "serviceprincipal-delete"),
    ("GET", "/servicePrincipals/{id}/owners", "serviceprincipal-list-owners"),
    ("POST", "/servicePrincipals/{id}/owners/$ref", "serviceprincipal-post-owners"),
    (
        "DELETE",
        "/servicePrincipals/{id}/owners/{owner_id}/$ref",
        "serviceprincipal-delete-owners",
    ),
    ("GET", "/servicePrincipals/{id}/memberOf", "serviceprincipal-list-memberof"),
    (
        "GET",
        "/servicePrincipals/{id}/appRoleAssignedTo",
        "serviceprincipal-list-approleassignedto",
    ),
    (
        "POST",
        "/servicePrincipals/{id}/appRoleAssignedTo",
        "serviceprincipal-post-approleassignedto",
    ),
    (
        "POST",
        "/servicePrincipals/{id}/appRoleAssignedTo/$ref",
        "serviceprincipal-post-approleassignedto",
    ),
    (
        "DELETE",
        "/servicePrincipals/{id}/appRoleAssignedTo/{assignment_id}",
        "serviceprincipal-delete-approleassignedto",
    ),
    (
        "GET",
        "/servicePrincipals/{id}/appRoleAssignments",
        "serviceprincipal-list-approleassignments",
    ),
    (
        "POST",
        "/servicePrincipals/{id}/appRoleAssignments",
        "serviceprincipal-post-approleassignments",
    ),
    (
        "DELETE",
        "/servicePrincipals/{id}/appRoleAssignments/{assignment_id}",
        "serviceprincipal-delete-approleassignments",
    ),
    (
        "GET",
        "/servicePrincipals/{id}/oauth2PermissionGrants",
        "serviceprincipal-list-oauth2permissiongrants",
    ),

    ("GET", "/oauth2PermissionGrants", "oauth2permissiongrant-list"),
    ("POST", "/oauth2PermissionGrants", "oauth2permissiongrant-post"),
    ("GET", "/oauth2PermissionGrants/{id}", "oauth2permissiongrant-get"),
    ("PATCH", "/oauth2PermissionGrants/{id}", "oauth2permissiongrant-update"),
    ("DELETE", "/oauth2PermissionGrants/{id}", "oauth2permissiongrant-delete"),

    ("GET", "/directoryRoles", "directoryrole-list"),
    ("POST", "/directoryRoles", "directoryrole-post-directoryroles"),
    ("GET", "/directoryRoles/{id}", "directoryrole-get"),
    ("GET", "/directoryRoles/{id}/members", "directoryrole-list-members"),
    ("POST", "/directoryRoles/{id}/members/$ref", "directoryrole-post-members"),
    (
        "DELETE",
        "/directoryRoles/{id}/members/{member_id}/$ref",
        "directoryrole-delete-member",
    ),
    ("GET", "/directoryRoleTemplates", "directoryroletemplate-list"),
    ("GET", "/directoryRoleTemplates/{id}", "directoryroletemplate-get"),

    (
        "GET",
        "/roleManagement/directory/roleDefinitions",
        "rbacapplication-list-roledefinitions",
    ),
    (
        "GET",
        "/roleManagement/directory/roleDefinitions/{id}",
        "unifiedroledefinition-get",
    ),
    (
        "GET",
        "/roleManagement/directory/roleAssignments",
        "rbacapplication-list-roleassignments",
    ),
    (
        "POST",
        "/roleManagement/directory/roleAssignments",
        "rbacapplication-post-roleassignments",
    ),
    (
        "GET",
        "/roleManagement/directory/roleAssignments/{id}",
        "unifiedroleassignment-get",
    ),
    (
        "DELETE",
        "/roleManagement/directory/roleAssignments/{id}",
        "unifiedroleassignment-delete",
    ),

    ("GET", "/domains", "domain-list"),
    ("GET", "/domains/{id}", "domain-get"),
    ("GET", "/organization", "organization-list"),
    ("GET", "/organization/{id}", "organization-get"),

    ("POST", "/directoryObjects/getByIds", "directoryobject-getbyids"),
]

# Routes where the published Application row cannot be used as-is. Each entry needs a reason,
# because overriding Microsoft's own table is exactly the kind of decision that should not be
# made silently.
OVERRIDES = {
    ("GET", "/users/{id}/memberOf"): {
        "reason": (
            "The published table reports no application permission, but the same page's note "
            "says application permissions are unsupported only for the /me/memberOf form. The "
            "addressed-user form accepts the same permissions as reading the user, plus the "
            "group-membership read permission the delegated column lists."
        ),
        "roles": [
            ["User.Read.All"],
            ["User.ReadWrite.All"],
            ["GroupMember.Read.All"],
            ["Directory.Read.All"],
            ["Directory.ReadWrite.All"],
        ],
    },
}

# The row label, in tables keyed by permission type.
APPLICATION_ROW = "Application"
DELEGATED_ROW = "Delegated (work or school account)"

NOT_AVAILABLE = {"not available.", "not supported.", "none.", "not applicable.", ""}

# A table whose first column is the permission type is keyed by row; anything else, such as the
# per-resource tables, names the permission type in a column header instead.
TYPE_KEYED_HEADER = "permission type"


def tables(text):
    """Yield every markdown table in `text` as (header cells, data rows)."""
    header = None
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if set("".join(cells)) <= set(":-") and cells:
                # The alignment row that follows a header.
                continue
            if header is None:
                header = cells
            else:
                rows.append(cells)
            continue
        if header is not None:
            yield header, rows
            header, rows = None, []
    if header is not None:
        yield header, rows


def permissions_section(text):
    """The Permissions section of an API reference page."""
    match = re.search(r"^## Permissions\b(.*?)(?=^## )", text, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def cells_for(text, permission_type):
    """Collect every cell in `text` that lists permissions of `permission_type`."""
    found = []
    for header, rows in tables(text):
        if not header:
            continue
        if header[0].strip().lower() == TYPE_KEYED_HEADER:
            # Keyed by row: the type names the row, and every later column lists permissions.
            for row in rows:
                if row and row[0].strip() == permission_type:
                    found.extend(row[1:])
        else:
            # Keyed by column: the type names a column, and every data row contributes.
            try:
                column = next(
                    index
                    for index, name in enumerate(header)
                    if name.strip() == permission_type
                )
            except StopIteration:
                continue
            for row in rows:
                if len(row) > column:
                    found.append(row[column])
    return found


def alternatives(cells):
    """Turn the published cells into a list of alternatives, each a list of permissions."""
    found = []
    for cell in cells:
        if cell.strip().lower() in NOT_AVAILABLE:
            continue
        for alternative in cell.split(","):
            # Strip the markdown links and emphasis the docs use.
            alternative = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", alternative)
            alternative = alternative.replace("*", "").strip()
            if not alternative or alternative.lower() in NOT_AVAILABLE:
                continue
            # A conjunction means every named permission is required together.
            required = [
                part.strip()
                for part in re.split(r"\s+and\s+", alternative)
                if part.strip()
            ]
            # Only real permission names, which are dotted identifiers.
            if required and all(re.fullmatch(r"[A-Za-z0-9.\-]+", part) for part in required):
                found.append(required)
    # Preserve order while removing duplicates, so the output is stable.
    unique = []
    for entry in found:
        if entry not in unique:
            unique.append(entry)
    return unique


def document_text(root, document):
    """The published permission text for an operation, from its include file or its API page."""
    include = os.path.join(root, "includes", "permissions", f"{document}-permissions.md")
    if os.path.exists(include):
        with open(include, encoding="utf-8") as handle:
            return handle.read(), f"includes/permissions/{document}-permissions.md"

    page = os.path.join(root, "api", f"{document}.md")
    if os.path.exists(page):
        with open(page, encoding="utf-8") as handle:
            return permissions_section(handle.read()), f"api/{document}.md"

    return None, None


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    source, destination = sys.argv[1], sys.argv[2]
    requirements = []
    missing = []

    for method, path, document in ROUTES:
        text, origin = document_text(source, document)
        if text is None:
            missing.append(f"{method} {path} -> {document} (no such document)")
            continue

        roles = alternatives(cells_for(text, APPLICATION_ROW))
        scopes = alternatives(cells_for(text, DELEGATED_ROW))

        override = OVERRIDES.get((method, path))
        if override:
            roles = override["roles"]
            origin = f"{origin} (overridden: {override['reason']})"

        if not roles:
            missing.append(f"{method} {path} -> {origin} (no application permissions parsed)")
            continue

        requirements.append(
            {
                "method": method,
                "path": path,
                "roles": roles,
                "scopes": scopes,
                "source": origin,
            }
        )

    if missing:
        # Enforcing a route with no requirement would silently permit everything, so a mapping
        # that does not resolve is a hard failure rather than a warning.
        print("could not resolve the published permissions for:", file=sys.stderr)
        for entry in missing:
            print(f"  {entry}", file=sys.stderr)
        return 1

    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(requirements, handle, indent=2)
        handle.write("\n")

    print(f"wrote permission requirements for {len(requirements)} routes to {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
