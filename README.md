# tf-aws-eks-cognito-auth-demo

Terraform demo for deploying an Amazon EKS cluster with AWS Cognito authentication, shared ALB, and ArgoCD integration.

## Features

- **Amazon EKS Cluster** with managed node groups
- **AWS Cognito User Pool** for authentication
- **Shared Application Load Balancer (ALB)** with Cognito authentication
- **ArgoCD** deployment with OIDC integration
- **Route53** DNS integration
- **AWS Load Balancer Controller** for Kubernetes ingress
- **EBS CSI Driver** for persistent volumes
- **Cognito User Groups** with ArgoCD RBAC integration
- **Test Users** management via Terraform

## Architecture

```plaintext
┌─────────────────┐
│   Route53 DNS   │
│ platform.*.com  │
└────────┬────────┘
         │
┌────────▼────────┐
│  Shared ALB     │
│  (Cognito Auth) │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
┌───▼───┐ ┌──▼────┐
│ArgoCD │ │Landing│
│  UI   │ │  Page │
└───────┘ └───────┘
    │
┌───▼──────────┐
│  EKS Cluster │
│  + Node     │
│    Groups   │
└─────────────┘
```

## Prerequisites

- Terraform >= 1.6.0
- AWS CLI configured with appropriate credentials
- kubectl installed
- Domain name with Route53 hosted zone (for HTTPS)
- ACM certificate (for HTTPS)

## Quick Start

1. **Clone the repository**

```bash
git clone <repository-url>
cd tf-aws-eks-cognito-auth-demo
```

1. **Configure variables**

Copy the example variables file and customize:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
domain_name         = "example.com"
enable_https        = true
certificate_arn     = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERT_ID"
enable_shared_alb   = true
enable_cognito_auth = true
```

1. **Set AWS Profile (optional)**

```bash
export AWS_PROFILE=your-profile
```

1. **Initialize and apply**

```bash
terraform init
terraform plan
terraform apply
```

## Configuration

### Required Variables

- `domain_name` - Your domain name (e.g., "example.com")
- `certificate_arn` - ACM certificate ARN (required if `enable_https = true`)

### Optional Variables

- `cluster_name` - EKS cluster name (default: "test")
- `cluster_version` - Kubernetes version (default: "1.34")
- `region` - AWS region (default: "ap-southeast-2")
- `enable_https` - Enable HTTPS (default: false)
- `enable_shared_alb` - Enable shared ALB (default: false)
- `enable_cognito_auth` - Enable Cognito authentication (default: false)
- `enable_cognito_test_users` - Create test users (default: false)
- `shared_alb_allowed_ips` - IP restrictions for ALB (default: ["0.0.0.0/0"])

### Cognito Test Users

To create test users via Terraform, configure in `terraform.tfvars`:

```hcl
enable_cognito_test_users = true
cognito_test_users = [
  {
    email     = "admin@example.com"
    username  = "admin-user"
    group_name = "argocd-admin"
  },
  {
    email     = "devops@example.com"
    username  = "devops-user"
    group_name = "argocd-devops"
  }
]
```

Users will receive an email with their temporary password from Cognito.

## Cognito Groups and ArgoCD RBAC

### Cognito Groups

The following Cognito groups are created automatically:

- `argocd-admin` - Full administrative access
- `argocd-platform` - Platform team (manage clusters, repos, projects)
- `argocd-devops` - DevOps team (manage applications in specific projects)
- `argocd-auditor` - Read-only access

### Group to Role Mapping

Cognito groups are mapped to ArgoCD roles in `modules/argocd/external/rbac-policy.csv`:

```csv
g, argocd-admin, role:admin
g, argocd-platform, role:platform
g, argocd-devops, role:devops
g, argocd-auditor, role:readonly
```

### Assigning Users to Groups

**Via Terraform (Recommended):**

Configure users in `terraform.tfvars` with the desired `group_name`:

```hcl
cognito_test_users = [
  {
    email     = "user@example.com"
    username  = "username"
    group_name = "argocd-admin"  # Assign to admin group
  }
]
```

**Via AWS CLI (for users not managed by Terraform):**

```bash
aws cognito-idp admin-add-user-to-group \
  --user-pool-id $(terraform output -raw cognito_user_pool_id) \
  --username <username> \
  --group-name argocd-admin \
  --profile <your-profile>
```

### RBAC Policy Management

ArgoCD RBAC policies are defined in `modules/argocd/external/rbac-policy.csv`. To modify permissions:

1. Edit `modules/argocd/external/rbac-policy.csv`
2. Run `terraform apply` to update the ConfigMap

See `modules/argocd/RBAC.md` for detailed RBAC documentation.

## Outputs

After deployment, retrieve important values:

```bash
# Platform URL
terraform output platform_url

# Cognito information
terraform output cognito_user_pool_id
terraform output cognito_hosted_ui_url

# ArgoCD credentials (sensitive)
terraform output -json argocd_username
terraform output -json argocd_password
```

## Accessing ArgoCD

1. **Get the platform URL:**

```bash
PLATFORM_URL=$(terraform output -raw platform_url)
echo "ArgoCD URL: ${PLATFORM_URL}/argocd"
```

1. **Open in browser** and click "LOG IN VIA OIDC"

2. **Login with Cognito credentials** (check email for temporary password)

3. **Verify RBAC permissions** based on your assigned group

## Security Considerations

### Secrets Management

- **terraform.tfvars** contains sensitive data and is gitignored
- **terraform.tfstate** files contain secrets and are gitignored
- Passwords are auto-generated and sent via email (not stored in Terraform state)
- ArgoCD password output is marked as sensitive

### IP Restrictions

Restrict ALB access by configuring `shared_alb_allowed_ips`:

```hcl
shared_alb_allowed_ips = ["1.2.3.4/32", "10.0.0.0/8"]
```

### Test Users

Set `enable_cognito_test_users = false` in production environments.

## Module Structure

```plaintext
.
├── main.tf                 # Root module configuration
├── variables.tf            # Variable definitions
├── outputs.tf              # Output definitions
├── terraform.tfvars        # Your configuration (gitignored)
├── terraform.tfvars.example # Example configuration
├── cognito-test-users.tf   # Test users management
└── modules/
    ├── vpc/                # VPC and networking
    ├── eks/                # EKS cluster and node groups
    ├── cognito/            # Cognito User Pool
    ├── argocd/             # ArgoCD deployment
    ├── route53/            # DNS configuration
    └── landing-page/       # Landing page service
```

## Troubleshooting

### ALB Not Created

The ALB is created by the AWS Load Balancer Controller when a Kubernetes Ingress is created. Ensure:

1. ArgoCD module is enabled
2. `enable_shared_alb = true`
3. Wait for Ingress to be created, then run `terraform apply` again

### Cognito Email Not Received

- Check spam folder
- Verify email address is correct
- Ensure Cognito email configuration is correct
- Check CloudWatch logs for Cognito email delivery

### ArgoCD OIDC Login Fails

- Verify Cognito groups are assigned to user
- Check ArgoCD server logs: `kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server`
- Verify OIDC configuration in `argocd-cm` ConfigMap
- Ensure callback URLs match in Cognito client configuration

### RBAC Not Working

- Verify user is in a Cognito group
- Check group name matches exactly (case-sensitive)
- Verify RBAC policy in `argocd-rbac-cm` ConfigMap
- Check ArgoCD server logs for group claims

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Note:** Test users managed by Terraform will be automatically deleted. Users created outside Terraform must be deleted manually.

## License

See [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and questions, please open an issue in the repository.
