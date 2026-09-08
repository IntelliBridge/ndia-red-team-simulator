# Cedar entities & schema note

`redsim-policy.cedar` evaluates against these Cedar types. A
`cedar-agent`-style host loads the policy + this schema, then for each
`/v1/is_authorized` request resolves the principal's role for the
target project before evaluation.

## Schema (sketch)

```cedarschema
entity User {
  email: String,
  is_system: Bool,
  // role resolved by the host from subject.project_memberships[resource.project_id]
  role: String,
};

entity Project;

action "scan.start", "agent.run", "agent.execute", "fix.generate",
       "fix.apply", "verify.replay", "target.manage", "audit.verify",
       "run.cancel", "tool.invoke"
  appliesTo {
    principal: [User],
    resource: [Project],
  };
```

## Request mapping

The `CedarPolicyEngine` POSTs `{ principal, action, resource, context }`
where:

- `principal` = the Redsim subject dict (`sub`, `email`, `is_system`,
  `project_memberships`).
- `action` = the `Action` value string, e.g. `"fix.apply"`.
- `resource` = `{ "project_id": "<id>", ... }`.
- `context` = request-time flags (e.g. `override_authorized`).

The host binds `principal.role` from
`principal.project_memberships[resource.project_id]` (absent membership →
no role → every project-scoped `permit` fails → `Deny`), then evaluates.
A `Deny` decision (or any error / unreachable agent) makes the engine
fail closed.

## Decision contract

Response body: `{ "decision": "Allow" | "Deny", "reason": "<optional>" }`.
