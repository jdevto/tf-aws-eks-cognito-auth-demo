# tf-aws-eks-cognito-auth-demo

Terraform demo: EKS cluster with Argo CD and Cognito OIDC login.

## What it does

- **VPC** (cloudbuildlab/vpc) and **EKS** (tfstack/eks-basic) with a managed node group
- **Cognito user pool** (tfstack/cognito) with hosted UI, one app client, and groups `admin` / `readonly`
- **Argo CD** (Helm) with OIDC to Cognito; server URL `https://argocd-test.<domain_name>`
- **Ingress** for Argo CD (when `certificate_arn` is set), with External DNS and AWS Load Balancer Controller

## Prerequisites

- Terraform >= 1.6
- AWS CLI and kubectl
- A domain and ACM certificate (for HTTPS ingress)

## Quick start

1. Copy and edit variables:

   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. Set in `terraform.tfvars` at least:
   - `domain_name` – your domain (e.g. `example.com`)
   - `certificate_arn` – ACM certificate ARN (or `""` to skip ingress)
   - `access_entries` – IAM principals that can access the cluster

3. Apply:

   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

## Variables

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `domain_name` | yes | — | Domain name (Argo CD host: `argocd-test.<domain_name>`) |
| `certificate_arn` | no | `""` | ACM certificate ARN for Argo CD ingress HTTPS |
| `cluster_name` | no | `"eks-1"` | EKS cluster name |
| `cluster_version` | no | `"1.35"` | Kubernetes version |
| `region` | no | `"ap-southeast-2"` | AWS region |
| `enable_https` | no | `false` | Enable HTTPS for ingress |
| `tags` | no | `{}` | Common tags |
| `access_entries` | no | `{}` | Map of EKS access entries (IAM principals + policies) |
| `cognito_user_username` | no | `null` | If set, creates one Cognito user (email = username) in group `admin` |

See `terraform.tfvars.example` for an `access_entries` example.

## Cognito and Argo CD

- **Cognito groups:** `admin`, `readonly`
- **Demo user:** Set `cognito_user_username` (e.g. an email) to create a user in group `admin`. Password is generated; use “Forgot password” or AWS Console to set a permanent one.
- **Argo CD URL:** `https://argocd-test.<domain_name>` (use the same hostname; callback URL is configured for it).
- **Login:** Open that URL → “LOG IN VIA OIDC” → sign in with Cognito.

RBAC is configured so Cognito groups map to Argo CD roles (e.g. `admin` → admin, `readonly` → readonly) via the Argo CD config in `main.tf`.

## Outputs

- **argocd_port_forward_command** – Steps to update kubeconfig, read initial admin secret, and port-forward to Argo CD (useful if ingress is not used).

## Accessing Argo CD

- **Via ingress (if `certificate_arn` is set):**
  `https://argocd-test.<domain_name>`
  Ensure DNS for that host points at the ALB (e.g. via External DNS).
- **Via port-forward:**
  Run the commands from `terraform output argocd_port_forward_command`.

## Cleanup

  ```bash
  terraform destroy
  ```
