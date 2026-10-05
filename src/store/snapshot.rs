//! Loading and dumping the whole directory.
//!
//! A snapshot is the directory's own entities, so a file dumped from one run loads into the
//! next. The one wrinkle is client secrets: they are deliberately not serialised with an
//! application, because Graph never discloses them on read, so a snapshot carries them in a
//! separate section. Without that, reloading a snapshot would produce applications that exist
//! but cannot authenticate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::store::Directory;
use crate::store::model::{
    AppRoleAssignment, Application, DirectoryRole, Group, OAuth2PermissionGrant, ServicePrincipal,
    User,
};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Snapshot {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub applications: Vec<Application>,
    pub service_principals: Vec<ServicePrincipal>,
    pub app_role_assignments: Vec<AppRoleAssignment>,
    pub oauth2_permission_grants: Vec<OAuth2PermissionGrant>,
    pub directory_roles: Vec<DirectoryRole>,
    /// Group membership and ownership, which are navigation properties and so are not carried
    /// on the group itself.
    pub group_links: Vec<GroupLinks>,
    /// Directory role membership, likewise a navigation property.
    pub role_members: Vec<RoleMembers>,
    /// Application and service principal owners.
    pub owners: Vec<OwnerLinks>,
    /// Client secrets, which an application never discloses on read.
    pub secrets: Vec<SecretValue>,
    /// User passwords, which Graph likewise never returns.
    pub passwords: Vec<PasswordValue>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupLinks {
    pub group_id: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub owners: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleMembers {
    pub role_id: String,
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerLinks {
    pub object_id: String,
    #[serde(default)]
    pub owners: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretValue {
    /// The owning application's object ID.
    pub application_id: String,
    pub key_id: String,
    pub secret_text: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordValue {
    pub user_id: String,
    pub password: String,
}

impl Snapshot {
    /// Capture the directory.
    pub fn capture(directory: &Directory) -> Self {
        Self {
            users: directory.users.values().cloned().collect(),
            groups: directory.groups.values().cloned().collect(),
            applications: directory.applications.values().cloned().collect(),
            service_principals: directory.service_principals.values().cloned().collect(),
            app_role_assignments: directory.app_role_assignments.values().cloned().collect(),
            oauth2_permission_grants: directory
                .oauth2_permission_grants
                .values()
                .cloned()
                .collect(),
            directory_roles: directory.directory_roles.values().cloned().collect(),
            group_links: directory
                .groups
                .values()
                .filter(|group| !group.members.is_empty() || !group.owners.is_empty())
                .map(|group| GroupLinks {
                    group_id: group.id.clone(),
                    members: group.members.clone(),
                    owners: group.owners.clone(),
                })
                .collect(),
            role_members: directory
                .directory_roles
                .values()
                .filter(|role| !role.members.is_empty())
                .map(|role| RoleMembers {
                    role_id: role.id.clone(),
                    members: role.members.clone(),
                })
                .collect(),
            owners: directory
                .applications
                .values()
                .map(|application| (application.id.clone(), application.owners.clone()))
                .chain(
                    directory
                        .service_principals
                        .values()
                        .map(|principal| (principal.id.clone(), principal.owners.clone())),
                )
                .filter(|(_, owners)| !owners.is_empty())
                .map(|(object_id, owners)| OwnerLinks { object_id, owners })
                .collect(),
            secrets: directory
                .applications
                .values()
                .flat_map(|application| {
                    application
                        .password_credentials
                        .iter()
                        .map(move |credential| SecretValue {
                            application_id: application.id.clone(),
                            key_id: credential.key_id.clone(),
                            secret_text: credential.secret_text.clone(),
                        })
                })
                .collect(),
            passwords: directory
                .users
                .values()
                .filter_map(|user| {
                    user.password.as_ref().map(|password| PasswordValue {
                        user_id: user.id.clone(),
                        password: password.clone(),
                    })
                })
                .collect(),
        }
    }

    /// Build a directory from the snapshot.
    pub fn restore(self) -> Directory {
        let mut directory = Directory {
            users: by_id(self.users, |user| user.id.clone()),
            groups: by_id(self.groups, |group| group.id.clone()),
            applications: by_id(self.applications, |application| application.id.clone()),
            service_principals: by_id(self.service_principals, |principal| principal.id.clone()),
            app_role_assignments: by_id(self.app_role_assignments, |assignment| {
                assignment.id.clone()
            }),
            oauth2_permission_grants: by_id(self.oauth2_permission_grants, |grant| {
                grant.id.clone()
            }),
            directory_roles: by_id(self.directory_roles, |role| role.id.clone()),
        };

        // Reattach everything the entities do not carry themselves.
        for links in self.group_links {
            if let Some(group) = directory.groups.get_mut(&links.group_id) {
                group.members = links.members;
                group.owners = links.owners;
            }
        }
        for links in self.role_members {
            if let Some(role) = directory.directory_roles.get_mut(&links.role_id) {
                role.members = links.members;
            }
        }
        for links in self.owners {
            if let Some(application) = directory.applications.get_mut(&links.object_id) {
                application.owners = links.owners;
            } else if let Some(principal) = directory.service_principals.get_mut(&links.object_id) {
                principal.owners = links.owners;
            }
        }
        for secret in self.secrets {
            if let Some(application) = directory.applications.get_mut(&secret.application_id)
                && let Some(credential) = application
                    .password_credentials
                    .iter_mut()
                    .find(|credential| credential.key_id == secret.key_id)
            {
                credential.secret_text = secret.secret_text;
            }
        }
        for password in self.passwords {
            if let Some(user) = directory.users.get_mut(&password.user_id) {
                user.password = Some(password.password);
            }
        }

        directory
    }
}

fn by_id<T>(items: Vec<T>, key: impl Fn(&T) -> String) -> BTreeMap<String, T> {
    items.into_iter().map(|item| (key(&item), item)).collect()
}
