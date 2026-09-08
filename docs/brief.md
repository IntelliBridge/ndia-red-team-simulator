# AI Assurance — Project Brief

> Foundation document for redsim. Reproduced from the team's Replit project
> brief (2026-09-08). Where the design spec and this brief differ, this brief
> wins.

## Status and purpose

This is a team kickoff brief, not an implemented product or an approved final
specification. It consolidates the supplied use case and the subsequent
reference analysis so collaborators can make informed scope decisions.

The immediate goal is to organize a shared project. The proposed next
milestone is a general-purpose, non-operational proof of concept using public
or synthetic data.

## Original context

The supplied document describes a military AI red-teaming concept: users
select or connect a model, run adversarial evaluation, inspect visual
explanations, and review mitigation recommendations.

Its requested interface places explanation outputs and recommendations side by
side. It references the Adversarial Robustness Toolbox (ART) and SHAP, and
discusses both evasion and data poisoning.

This source context is preserved for traceability; it is not authorization to
build or optimize combat targeting, weapons, or operational military decision
systems. Those applications are outside this starter project's scope.

The original document alternates between "DoD" and "DoW." The intended
terminology remains unconfirmed.

Source: original supplied document, unchanged.

### Original use-case text

The DoD is rapidly deploying AI and Machine Learning models to the tactical
edge for target recognition, threat detection, and decision support. However,
these models are highly vulnerable to adversarial attacks, such as data
poisoning or evasion techniques.

This concept is an automated "Red Team" simulator designed to stress-test
military AI models before they hit the battlefield. Users can upload a model
(or connect via API), and this will automatically generate adversarial
examples designed to trick the system. Beyond just breaking the model, the
tool uses explainability frameworks (like SHAP) to show exactly why the model
failed (e.g., "The model was over-reliant on the background pixels rather than
the target"). It then outputs natural language recommendations for hardening
the AI.

*Requirements.* Build an automated red-teaming tool that evaluates the
robustness of DoW AI models by generating adversarial attacks, utilizing
explainable AI to map vulnerabilities, and recommending defensive
countermeasures.

*Expected deliverables.* A web UI where a user can select a model, trigger an
adversarial attack, and view the SHAP visual outputs and mitigation
recommendations side-by-side.

*Resources.* ART https://github.com/Trusted-AI/adversarial-robustness-toolbox ·
SHAP https://shap.readthedocs.io/en/latest/ · garak https://github.com/NVIDIA/garak

## Reference map

| Reference | Role in the analysis | Limitations to retain |
|---|---|---|
| ART | A library for evaluating conventional ML against multiple adversarial threat categories. | Framework coverage does not guarantee compatibility with every uploaded model or evaluation pipeline. |
| SHAP | Feature attribution and local explanations, including image and text applications. | Attribution is not proof of causality or a definitive explanation of why a failure occurred. |
| NVIDIA garak | Modular LLM vulnerability scanning, detectors, and structured reports. | Not a replacement for conventional ML evaluation or complete agent/application testing. |
| The TIP of the Iceberg — ACL 2025 | Research on Task-in-Prompt failures and the PHRYGE benchmark, informing possible LLM coverage. | The study covers six LLMs and text; automated evaluation has limitations. It does not validate countermeasures. Compatibility with garak has not been established. |
| OpenSandbox | Candidate execution-isolation and lifecycle infrastructure. | Not an evaluation engine or a model defense. Effective isolation depends on the runtime and configuration. No runtime has been installed or validated here. |

The references describe complementary layers, not interchangeable tools or a
pre-integrated stack.

## Proposed first milestone

Demonstrate a single, benign evaluation workflow with traceable evidence and
human review:

1. Identify an approved public or synthetic evaluation target and dataset.
2. Record the evaluation purpose, assumptions, and test coverage.
3. Perform a bounded, non-operational assessment.
4. Display observed results and supporting evidence.
5. Separate observations, interpretation, and candidate recommendations.
6. Save a report that states limitations and supports a follow-up comparison.

Choose one evaluation domain first:

- Conventional ML: prediction behavior and input sensitivity.
- LLM assistant: observable behavior against defined safety and quality requirements.
- Agent application: behavior involving tools, files, and permission
  boundaries; a separate scope requiring additional review.

The earlier image-classification-first recommendation was an assumption, not
an approved choice. The additional LLM references do not establish approval to
implement all domains at once.

## Reporting principles

- Match the evidence to the evaluated system; do not require SHAP for every modality.
- Distinguish observed behavior from inferred causes.
- Record model and dataset versions, test configuration, evaluator configuration, and run limitations.
- Present results by test family with clear denominators and coverage. Avoid a universal score that mixes unrelated domains.
- Include benign controls and human review of flagged examples.
- Label any illustrative results as illustrative. Do not invent completed runs, measured improvements, or validated fixes.
- Treat recommendations as candidates until supported by a separate evaluation.
- State that passing a test suite does not establish complete safety or operational readiness.

## Open decisions

| Decision | Current position | Suggested participants |
|---|---|---|
| First domain and benign use case | Open; select one before implementation | Product lead and evaluation researcher |
| Model access method | Open; uploaded artifacts and API access have different risks and capabilities | Evaluation researcher and security reviewer |
| Dataset and handling rules | Public or synthetic, non-sensitive data proposed | Product lead and security reviewer |
| Evaluation criteria | Open; define measurable, domain-specific criteria | Evaluation researcher and independent reviewer |
| Evidence presentation | Appropriate evidence plus recommendations; universal SHAP requirement not assumed | Product designer and evaluation researcher |
| Execution environment | Open; OpenSandbox is a candidate, not an installed dependency | Platform engineer and security reviewer |
| Team roles and ownership | Unassigned | Project owner |

No software implementation, provider authorization, deployment, spending
commitment, or collaborator invitation is implied by this brief.

## Not in the first milestone

- Operational or sensitive datasets and live mission-system connections.
- Combat targeting, weapons integration, or optimization of operational military models.
- Unrestricted execution of uploaded model artifacts.
- A training-data poisoning pipeline.
- Simultaneous support for conventional ML, LLMs, and agents.
- Autonomous application of proposed mitigations.
- Claims of certification, causal certainty, or deployment readiness.

## Completion criteria for the proposed proof of concept

- A teammate can understand and follow one documented benign workflow.
- Every reported finding links to observable evidence.
- The report preserves enough configuration to support a meaningful rerun; nondeterminism is disclosed.
- Interpretation and recommendations are distinguishable from measurements.
- Data handling and execution boundaries receive review before accepting uploads or external connections.
- Known limitations and unsupported paths are visible, not silently bypassed.

## Decisions taken for redsim (2026-09-08)

Recorded here so the open decisions above have a traceable answer for this
proof of concept. See `docs/superpowers/specs/2026-09-08-redsim-design.md`.

- **First domain:** image classification on CIFAR-10 (public, benign). Tabular
  and LLM domains are registered as not implemented.
- **Model access:** bundled model only. No uploads, no external endpoints. The
  LLM stub describes a connection through Pythia (IntelliBridge's
  OpenAI-compatible agent gateway: base URL, `pk_…` key, persona, canonical
  `<vendor>/<model>` id) so the connection shape is real, but launching returns
  HTTP 501.
- **LLM gateway:** any LLM call redsim makes (the optional recommendation
  narrative) goes through Pythia, so redsim never holds a provider credential
  and Pythia's guardrails, metering and audit apply. Default off.
- **Dataset:** CIFAR-10 test split, fetched from the HuggingFace mirror
  (`uoft-cs/cifar10`) with torchvision as fallback.
- **Evaluation criteria:** clean vs. adversarial vs. random-noise-control
  accuracy per test family, with denominators; per-class counts; L∞ / L2
  perturbation norms; a labelled heuristic attribution-concentration metric.
- **Evidence presentation:** measurements, observations, interpretation and
  candidate recommendations are separate fields and separate UI panels.
- **Execution environment:** in-process, local, no sandbox. Acceptable because
  no untrusted code or artifacts are executed in this milestone.

## Additional references

- https://github.com/IntelliBridge/pythia (agent gateway used for any LLM access)

- https://github.com/NVIDIA/garak
- https://aclanthology.org/2025.acl-long.334/
- https://github.com/opensandbox-group/OpenSandbox
