# Feature Specification: <name>

**Feature:** <ID and folder>  
**Status:** Draft — not approved for implementation  
**Owner / reviewer:** Unassigned  
**Source:** <brief section or agreed user need>

## Outcome and scope

Describe the problem and user value. List explicit exclusions. Keep technical choices in `plan.md`.

## User Scenarios & Testing

### US1 — <independently useful outcome> (P1)

As <role>, I want <behavior>, so that <benefit>.

**Independent test:** <how to demonstrate this story by itself>.

1. **Given** <starting state>, **When** <action>, **Then** <observable result>.
2. **Given** <error or denied state>, **When** <action>, **Then** <observable result>.

## Functional Requirements

- **FR-001:** The system must <specific observable behavior>.
- **FR-002:** The system must <permission or failure behavior>.

## Key Entities

Define user-facing concepts, not an unreviewed database schema.

## Edge Cases

Address empty states, validation, permissions, concurrency, version changes, and lifecycle behavior relevant to this feature.

## Success Criteria

- **SC-001:** <measurable acceptance outcome; not an invented current result>.

## Assumptions and Clarifications

Separate assumptions from decisions. Link blockers to `specs/_shared/decisions.md`.