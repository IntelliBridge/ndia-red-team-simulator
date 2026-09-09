variable "account_id" {
  description = "Verified AWS account ID. This is an identifier, not a credential."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Provide the verified 12-digit account ID."
  }
}

variable "region" {
  description = "Approved P7 region. A region change requires a reviewed contract update."
  type        = string
  default     = "us-east-1"
  validation {
    condition     = var.region == "us-east-1"
    error_message = "The current foundation is scoped to us-east-1."
  }
}

variable "environment" {
  description = "Short environment name used in all resource names."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,7}$", var.environment))
    error_message = "Use 2-8 lowercase letters or digits, starting with a letter."
  }
}

variable "network" {
  description = "Explicit existing network selection. This module never selects a default VPC or creates NAT/Internet gateways."
  type = object({
    vpc_id             = string
    public_subnet_ids  = set(string)
    private_subnet_ids = set(string)
  })
  validation {
    condition = (
      can(regex("^vpc-[a-f0-9]+$", var.network.vpc_id)) &&
      length(var.network.public_subnet_ids) >= 2 &&
      length(var.network.private_subnet_ids) >= 2 &&
      length(setintersection(var.network.public_subnet_ids, var.network.private_subnet_ids)) == 0 &&
      alltrue([for id in setunion(var.network.public_subnet_ids, var.network.private_subnet_ids) : can(regex("^subnet-[a-f0-9]+$", id))])
    )
    error_message = "Select a VPC, at least two public and two private subnet IDs, with no overlap."
  }
}

variable "allow_public_https" {
  description = "Explicit opt-in for a publicly reachable HTTPS demo. Authentication remains required in the runtime."
  type        = bool
  default     = false
}

variable "reviewer_ipv4_cidrs" {
  description = "Approved team ingress ranges for future TLS access. No public listener is created by this foundation."
  type        = set(string)
  validation {
    condition = (
      length(var.reviewer_ipv4_cidrs) > 0 &&
      alltrue([for cidr in var.reviewer_ipv4_cidrs :
        can(cidrnetmask(cidr)) && (try(tonumber(split("/", cidr)[1]) >= 16, false) || (var.allow_public_https && cidr == "0.0.0.0/0"))
      ])
    )
    error_message = "Use IPv4 reviewer ranges of /16 or narrower, or explicitly opt into public HTTPS before supplying 0.0.0.0/0."
  }
}

variable "pythia_ipv4_cidrs" {
  description = "Optional approved gateway destination CIDRs. Only the default-worker SG gets HTTPS egress to them. Empty means no Pythia egress."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([for cidr in var.pythia_ipv4_cidrs :
      can(cidrnetmask(cidr)) && try(tonumber(split("/", cidr)[1]) >= 16, false)
    ])
    error_message = "Pythia destinations must be explicit IPv4 ranges of /16 or narrower."
  }
}

variable "existing_ecr_repository_names" {
  description = "Existing repositories, referenced only. Verify them before any separately approved rollout."
  type        = map(string)
  default = {
    api    = "ndia-red-team/api"
    worker = "ndia-red-team/worker"
    web    = "ndia-red-team/web"
  }
  validation {
    condition = (
      toset(keys(var.existing_ecr_repository_names)) == toset(["api", "worker", "web"]) &&
      alltrue([for name in values(var.existing_ecr_repository_names) : can(regex("^ndia-red-team/[a-z0-9-]+$", name))])
    )
    error_message = "Reference exactly the existing api, worker and web repositories under ndia-red-team/."
  }
}

variable "existing_deploy_role_name" {
  description = "Existing CI deployment role, output as a reference only. Never changed or granted Terraform permissions here."
  type        = string
  default     = "ndia-red-team-gha-deploy"
  validation {
    condition     = can(regex("^ndia-red-team-[a-zA-Z0-9+=,.@_-]+$", var.existing_deploy_role_name))
    error_message = "Reference an existing ndia-red-team-prefixed role."
  }
}

variable "runtime_secret_arns" {
  description = "External Secrets Manager references per future service. Never supply secret values; the migration role alone additionally receives the RDS-managed master secret reference."
  type        = map(set(string))
  default     = {}
  validation {
    condition = (
      length(setsubtract(toset(keys(var.runtime_secret_arns)), toset(["api", "web", "scans", "default", "beat", "migration", "assets", "identity"]))) == 0 &&
      alltrue(flatten([for arns in values(var.runtime_secret_arns) : [
        for arn in arns : can(regex("^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", arn)) &&
        try(split(":", arn)[4] == var.account_id, false)
      ]]))
    )
    error_message = "Use only supported service names and same-account Secrets Manager ARNs, never secret values or wildcards."
  }
}

variable "artifact_prefixes_by_service" {
  description = "Owner-approved object prefixes per artifact-using service. Empty grants no business S3 access. Prefixes are not invented from unimplemented ML code."
  type        = map(set(string))
  default     = {}
  validation {
    condition = (
      length(setsubtract(toset(keys(var.artifact_prefixes_by_service)), toset(["api", "scans", "default", "assets"]))) == 0 &&
      alltrue([for prefixes in values(var.artifact_prefixes_by_service) :
        length(prefixes) > 0 && alltrue([for prefix in prefixes :
          can(regex("^[A-Za-z0-9][A-Za-z0-9/_-]*[A-Za-z0-9_-]$", prefix)) && !strcontains(prefix, "//")
        ])
      ])
    )
    error_message = "Only api/scans/default/assets may receive explicit nonempty object prefixes without wildcards, traversal, or a trailing slash."
  }
}

variable "runtime_secret_kms_key_arns" {
  description = "Optional customer-managed secret-encryption keys per service, only where external secret references need them."
  type        = map(set(string))
  default     = {}
  validation {
    condition = (
      length(setsubtract(toset(keys(var.runtime_secret_kms_key_arns)), toset(keys(var.runtime_secret_arns)))) == 0 &&
      alltrue(flatten([for arns in values(var.runtime_secret_kms_key_arns) : [
        for arn in arns : can(regex("^arn:aws:kms:us-east-1:[0-9]{12}:key/[a-f0-9-]+$", arn)) &&
        try(split(":", arn)[4] == var.account_id, false)
      ]]))
    )
    error_message = "KMS references must be same-account key ARNs for services with external secret references."
  }
}
