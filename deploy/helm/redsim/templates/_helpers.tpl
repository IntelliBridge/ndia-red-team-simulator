{{/*
Naming + label helpers for the Redsim chart.
*/}}

{{/* Chart name (overridable). */}}
{{- define "redsim.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. If fullnameOverride is set it wins; otherwise the
release name is used (and de-duplicated if it already contains the chart
name) so component names render as "<release>-api" etc.
*/}}
{{- define "redsim.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Chart label "name-version". */}}
{{- define "redsim.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every object. */}}
{{- define "redsim.labels" -}}
helm.sh/chart: {{ include "redsim.chart" . }}
{{ include "redsim.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: redsim
{{- end -}}

{{/* Selector labels (stable across upgrades). */}}
{{- define "redsim.selectorLabels" -}}
app.kubernetes.io/name: {{ include "redsim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Per-component name: "<fullname>-<component>".
Usage: {{ include "redsim.componentName" (dict "ctx" . "component" "api") }}
*/}}
{{- define "redsim.componentName" -}}
{{- printf "%s-%s" (include "redsim.fullname" .ctx) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Per-component selector labels (adds app.kubernetes.io/component).
Usage: {{ include "redsim.componentSelectorLabels" (dict "ctx" . "component" "api") }}
*/}}
{{- define "redsim.componentSelectorLabels" -}}
{{ include "redsim.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Per-component labels (common + component).
Usage: {{ include "redsim.componentLabels" (dict "ctx" . "component" "api") }}
*/}}
{{- define "redsim.componentLabels" -}}
{{ include "redsim.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Resolve a service image to a fully-qualified ref, applying the optional
global.imageRegistry prefix.
Usage: {{ include "redsim.image" (dict "ctx" . "image" .Values.api.image) }}
*/}}
{{- define "redsim.image" -}}
{{- $reg := .ctx.Values.global.imageRegistry -}}
{{- if $reg -}}
{{- printf "%s%s:%s" $reg .image.repository .image.tag -}}
{{- else -}}
{{- printf "%s:%s" .image.repository .image.tag -}}
{{- end -}}
{{- end -}}

{{/* Name of the config Secret (rendered or external). */}}
{{- define "redsim.secretName" -}}
{{- if .Values.config.secret.existingSecret -}}
{{- .Values.config.secret.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "redsim.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the config ConfigMap. */}}
{{- define "redsim.configMapName" -}}
{{- printf "%s-config" (include "redsim.fullname" .) -}}
{{- end -}}

{{/*
Production secret safety guard. `fail`s the render when the chart would ship
the built-in DEV secret placeholders into a prod environment with no
externally-managed secret wired in. A deployment is considered safe when ANY
of the following holds:
  - config.env != "prod" (dev/staging may use placeholders), OR
  - config.secret.existingSecret is set (operator pre-provisioned a Secret), OR
  - config.secret.externalSecrets.enabled (External Secrets Operator fills it).
Otherwise, if any secret value still equals its shipped dev placeholder, the
render aborts with actionable guidance. Self-contained (callable from any
template); takes the root context.
*/}}
{{- define "redsim.validateProdSecret" -}}
{{- $s := .Values.config.secret -}}
{{- if and (eq .Values.config.env "prod") (not $s.existingSecret) (not $s.externalSecrets.enabled) -}}
{{- $placeholders := list -}}
{{- if eq (toString $s.s3AccessKeyId) "redsim" -}}{{- $placeholders = append $placeholders "config.secret.s3AccessKeyId" -}}{{- end -}}
{{- if eq (toString $s.s3SecretAccessKey) "redsim-secret" -}}{{- $placeholders = append $placeholders "config.secret.s3SecretAccessKey" -}}{{- end -}}
{{- if eq (toString $s.betterAuthSecret) "dev-better-auth-secret-change-me-32chars" -}}{{- $placeholders = append $placeholders "config.secret.betterAuthSecret" -}}{{- end -}}
{{- if $placeholders -}}
{{- fail (printf "config.env=prod but these secret values are still the shipped DEV placeholders: %s. Refusing to deploy insecure secrets to production. Fix by either (a) overriding them with real values (--set or a sealed values file), (b) setting config.secret.existingSecret to a pre-provisioned Secret, or (c) setting config.secret.externalSecrets.enabled=true to source them from the External Secrets Operator." (join ", " $placeholders)) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Pod-level securityContext (non-root). Shared by all Redsim pods.
*/}}
{{- define "redsim.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
Container-level securityContext. Pass readOnlyRootFilesystem via the dict.
Usage: {{ include "redsim.containerSecurityContext" (dict "readOnlyRootFilesystem" true) }}
*/}}
{{- define "redsim.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: {{ .readOnlyRootFilesystem | default false }}
runAsNonRoot: true
runAsUser: 1000
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}
