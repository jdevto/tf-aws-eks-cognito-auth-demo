# ArgoCD RBAC Policy Management

This document explains how to maintain ArgoCD RBAC policies using the CSV file approach.

## File Structure

The RBAC policies are defined in `external/rbac-policy.csv` which is organized by role for easy maintenance.

## Policy File Format

The CSV file uses ArgoCD's policy format:

```csv
p, <role>, <resource>, <action>, <object>, <effect>
g, <group>, <role>
```

### Format Explanation

- **`p`** = Policy rule
- **`g`** = Group mapping (maps Cognito group to ArgoCD role)
- **`role`** = ArgoCD role name (e.g., `role:admin`, `role:readonly`)
- **`resource`** = ArgoCD resource type:
  - `applications` - ArgoCD applications
  - `clusters` - Kubernetes clusters
  - `repositories` - Git repositories
  - `projects` - ArgoCD projects
  - `accounts` - ArgoCD user accounts
  - `certificates` - TLS certificates
  - `logs` - Application logs
  - `exec` - Pod exec access
  - `gpgkeys` - GPG keys
- **`action`** = Action allowed:
  - `get` - Read/view
  - `create` - Create new
  - `update` - Modify existing
  - `delete` - Remove
  - `sync` - Sync applications
  - `action/*` - All actions
  - `*` - All actions (wildcard)
- **`object`** = Object scope:
  - `*` - All objects
  - `*/*` - All applications in all projects
  - `<project>/*` - All applications in specific project
  - `<project>/<app>` - Specific application
- **`effect`** = `allow` or `deny`

## Role Definitions

### role:admin

**Purpose:** Full administrative access to all ArgoCD resources

**Permissions:**

- All actions on all resources (applications, clusters, repositories, projects, accounts, certificates, logs, exec, gpgkeys)

**Cognito Group:** `argocd-admin`

**Use Case:** Platform administrators who need complete control

---

### role:platform

**Purpose:** Platform team managing infrastructure components

**Permissions:**

- Full access to applications, clusters, repositories, projects
- **No access** to accounts, certificates, or gpgkeys (admin-only)

**Cognito Group:** `argocd-platform`

**Use Case:** Platform engineers managing clusters, repos, and projects but not user accounts

---

### role:devops

**Purpose:** DevOps team managing applications

**Permissions:**

- Full application management (create, update, delete, sync)
- Read-only access to clusters, repositories, projects

**Cognito Group:** `argocd-devops`

**Use Case:** DevOps engineers who deploy and manage applications but don't manage infrastructure

---

### role:readonly

**Purpose:** Read-only access for auditors and viewers

**Permissions:**

- View applications, clusters, repositories, projects, logs
- Can sync applications (for viewing current state)

**Cognito Group:** `argocd-auditor`

**Use Case:** Auditors, stakeholders, or team members who need visibility but not modification rights

## Best Practices for Maintaining Roles

### 1. **Organize by Role Sections**

Each role should have a clear section with comments:

```csv
# ==============================================================================
# role:admin - Full administrative access
# ==============================================================================
p, role:admin, applications, *, */*, allow
...
```

### 2. **Use Comments for Documentation**

Add comments explaining:

- What the role is for
- What permissions it grants
- Who should have this role

### 3. **Group Related Permissions**

Keep permissions for the same resource together:

```csv
# Applications
p, role:devops, applications, get, *, allow
p, role:devops, applications, create, */*, allow
p, role:devops, applications, update, */*, allow
p, role:devops, applications, delete, */*, allow
p, role:devops, applications, sync, */*, allow

# Clusters (read-only)
p, role:devops, clusters, get, *, allow
```

### 4. **Use Project-Scoped Permissions When Possible**

Instead of wildcards, scope to specific projects:

```csv
# Instead of: p, role:devops, applications, create, */*, allow
# Use: p, role:devops, applications, create, my-project/*, allow
```

### 5. **Test Changes Incrementally**

- Make small changes
- Test with a non-admin user first
- Verify permissions work as expected

### 6. **Version Control**

- Commit policy changes to version control
- Use pull requests for review
- Document why permissions were changed

## Adding a New Role

1. **Define the role permissions** in `rbac-policy.csv`:

```csv
# ==============================================================================
# role:developer - Developers managing applications in their project
# ==============================================================================
p, role:developer, applications, get, dev-project/*, allow
p, role:developer, applications, create, dev-project/*, allow
p, role:developer, applications, update, dev-project/*, allow
p, role:developer, applications, sync, dev-project/*, allow
p, role:developer, repositories, get, *, allow
p, role:developer, projects, get, *, allow
```

1. **Map Cognito group to role**:

```csv
g, argocd-developer, role:developer
```

1. **Create the Cognito group** (in `modules/cognito/main.tf`):

```terraform
resource "aws_cognito_user_group" "argocd_developer" {
  name         = "argocd-developer"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "ArgoCD developers - manage applications in dev project"
}
```

## Modifying Existing Roles

1. **Edit `rbac-policy.csv`** - Find the role section and modify permissions
2. **Apply changes** - Run `terraform apply`
3. **Verify** - Test with a user in that role

## Custom Policy File

To use a custom policy file instead of the default:

```terraform
module "argocd" {
  # ... other variables ...
  rbac_policy_file = "/path/to/custom-rbac-policy.csv"
}
```

## Troubleshooting

### Policy not applying

- Check that `rbac-policy.csv` exists and is readable
- Verify CSV format is correct (no syntax errors)
- Check ArgoCD server logs: `kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server`

### User has wrong permissions

- Verify user is in correct Cognito group
- Check group mapping in CSV: `g, <group>, role:<role>`
- Verify OIDC token includes groups: Check ArgoCD logs for token claims

### Permission denied errors

- Check `policy.default` - users without explicit role get this
- Verify role has required permissions in CSV
- Check if project-scoped permissions are too restrictive

## References

- [ArgoCD RBAC Documentation](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/)
- [RBAC Policy Reference](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#rbac-policy-reference)
