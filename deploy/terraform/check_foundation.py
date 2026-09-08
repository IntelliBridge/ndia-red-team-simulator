#!/usr/bin/env python3
"""Credential-free regression guard for this deliberately non-running foundation.

This complements Terraform validation and mocked plan assertions. It is not an
AWS inventory, a general HCL security scanner, or proof of application security.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
ALLOWED_RESOURCES = {
    "aws_security_group",
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
    "aws_vpc_endpoint",
    "aws_lb",
    "aws_lb_target_group",
    "aws_ecs_cluster",
    "aws_cloudwatch_log_group",
    "aws_db_subnet_group",
    "aws_db_parameter_group",
    "aws_db_instance",
    "aws_elasticache_subnet_group",
    "aws_elasticache_parameter_group",
    "aws_elasticache_replication_group",
    "aws_s3_bucket",
    "aws_s3_bucket_versioning",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_object_lock_configuration",
    "aws_iam_role",
    "aws_iam_role_policy",
}
ALLOWED_DATA = {"aws_vpc", "aws_subnet", "aws_route_table"}


def main() -> int:
    errors = []
    files = sorted(ROOT.glob("*.tf"))
    if not files or not (ROOT / ".terraform.lock.hcl").is_file():
        errors.append("Terraform source and committed provider lockfile are required.")
    resources = []
    # Terraform also loads JSON and override configuration. Unsupported inputs
    # must fail closed, not slip past this intentionally bounded HCL guard.
    for path in ROOT.iterdir():
        if path.name.endswith((".tf.json", ".tfvars", ".tfvars.json", ".tftest.json", ".tftest.hcl")) or path.name in {
            "override.tf", "override.tf.json",
        } or path.name.endswith(("_override.tf", "_override.tf.json")):
            errors.append(f"{path.name}: unsupported local/JSON/override configuration")
    for path in (ROOT / "tests").rglob("*.json"):
        errors.append(f"{path.name}: JSON test inputs are unsupported")
    for path in files:
        if path.is_symlink():
            errors.append(f"{path.name}: symlinked configuration is unsupported")
            continue
        text = path.read_text()
        if re.search(r'\b(cloud|assume_role|assume_role_with_web_identity)\s*{', text):
            errors.append(f"{path.name}: remote execution or credential overrides are prohibited")
        if re.search(r'\b(alias|profile|shared_config_files|shared_credentials_files|endpoints)\s*(=|{)', text):
            errors.append(f"{path.name}: aliased provider or credential/endpoint overrides are prohibited")
        if any(provider != "aws" for provider in re.findall(r'^\s*provider\s+"([^"]+)"', text, re.M)):
            errors.append(f"{path.name}: only the default AWS provider is supported")
        if any(backend != "s3" for backend in re.findall(r'\bbackend\s+"([^"]+)"', text)):
            errors.append(f"{path.name}: only the documented S3 backend is supported")
        for resource in re.findall(r'^\s*resource\s+"([^"]+)"', text, re.M):
            resources.append(resource)
            if resource not in ALLOWED_RESOURCES:
                errors.append(f"{path.name}: out-of-scope managed resource {resource}")
        for data in re.findall(r'^\s*data\s+"([^"]+)"', text, re.M):
            if data not in ALLOWED_DATA:
                errors.append(f"{path.name}: unapproved data source {data}")
        if re.search(r'^\s*(module|provisioner)\s+"', text, re.M):
            errors.append(f"{path.name}: modules/provisioners need separate scope review")
        if re.search(
            r"^\s*(password|password_wo|auth_token|secret_string|secret_string_wo|"
            r"secret_binary|access_key|secret_key|token)\s*=",
            text,
            re.M,
        ):
            errors.append(f"{path.name}: secret-value argument is prohibited")
        if re.search(r"^\s*(force_destroy|publicly_accessible)\s*=\s*true", text, re.M):
            errors.append(f"{path.name}: destructive or public-data option")

    tests = sorted((ROOT / "tests").glob("*.tftest.hcl"))
    if not tests:
        errors.append("Mocked-provider tests are required.")
    for path in tests:
        text = path.read_text()
        runs = len(re.findall(r'^\s*run\s+"', text, re.M))
        plans = len(re.findall(r"^\s*command\s*=\s*plan\s*$", text, re.M))
        if not re.search(r'^\s*mock_provider\s+"aws"\s*{', text, re.M):
            errors.append(f"{path.name}: AWS must be mocked")
        if re.search(r"\balias\s*=", text):
            errors.append(f"{path.name}: the default AWS provider must be mocked, never only an alias")
        if runs == 0 or runs != plans:
            errors.append(f"{path.name}: every run must explicitly use command = plan")
        if re.search(r'^\s*(provider\s+"|providers\s*=|module\s*{)', text, re.M):
            errors.append(f"{path.name}: real provider/module substitution is prohibited")

    workflow = ROOT / "ci/p7-infra-checks.yml.example"
    if not workflow.is_file():
        errors.append("The scoped, inactive infrastructure validation template is required.")
    else:
        text = workflow.read_text()
        for forbidden in (
            "id-token", "aws-actions/", "secrets.", "workflow_dispatch",
            "terraform apply", "terraform destroy", "configure-aws-credentials",
        ):
            if forbidden in text:
                errors.append(f"{workflow.name}: prohibited activation/credential token {forbidden}")
        if "contents: read" not in text or "./validate.sh" not in text:
            errors.append("Workflow must declare read-only contents and run the checked validator.")

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"Foundation scope guard passed ({len(files)} Terraform files, "
          f"{len(resources)} resource blocks, {len(tests)} mock test files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())