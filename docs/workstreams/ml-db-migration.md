# Workstream: DB: migration 0010_ml_vertical + Target/Job kinds

Status: placeholder, work in progress (opened 2026-09-08).

Alembic migration 0010_ml_vertical per spec section 5: Target.kind ml_model_artifact / ml_model_endpoint, targets.detail, ml_campaigns table (attack set, eps grid, reference budget, scoring weights, MRI + subscores), Job.type additions, RLS policy + org_id trigger parity with existing tenant tables, model updates in aegis/db/models.py, sqlite-compatible tests.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
