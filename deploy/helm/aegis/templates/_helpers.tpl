{{/*
Naming + label helpers for the Aegis chart.
*/}}

{{/* Chart name (overridable). */}}
{{- define "aegis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. If fullnameOverride is set it wins; otherwise the
release name is used (and de-duplicated if it already contains the chart
name) so component names render as "<release>-api" etc.
*/}}
{{- define "aegis.fullname" -}}
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
{{- define "aegis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every object. */}}
{{- define "aegis.labels" -}}
helm.sh/chart: {{ include "aegis.chart" . }}
{{ include "aegis.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aegis
{{- end -}}

{{/* Selector labels (stable across upgrades). */}}
{{- define "aegis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Per-component name: "<fullname>-<component>".
Usage: {{ include "aegis.componentName" (dict "ctx" . "component" "api") }}
*/}}
{{- define "aegis.componentName" -}}
{{- printf "%s-%s" (include "aegis.fullname" .ctx) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Per-component selector labels (adds app.kubernetes.io/component).
Usage: {{ include "aegis.componentSelectorLabels" (dict "ctx" . "component" "api") }}
*/}}
{{- define "aegis.componentSelectorLabels" -}}
{{ include "aegis.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Per-component labels (common + component).
Usage: {{ include "aegis.componentLabels" (dict "ctx" . "component" "api") }}
*/}}
{{- define "aegis.componentLabels" -}}
{{ include "aegis.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Resolve a service image to a fully-qualified ref, applying the optional
global.imageRegistry prefix.
Usage: {{ include "aegis.image" (dict "ctx" . "image" .Values.api.image) }}
*/}}
{{- define "aegis.image" -}}
{{- $reg := .ctx.Values.global.imageRegistry -}}
{{- if $reg -}}
{{- printf "%s%s:%s" $reg .image.repository .image.tag -}}
{{- else -}}
{{- printf "%s:%s" .image.repository .image.tag -}}
{{- end -}}
{{- end -}}

{{/* Name of the config Secret (rendered or external). */}}
{{- define "aegis.secretName" -}}
{{- if .Values.config.secret.existingSecret -}}
{{- .Values.config.secret.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "aegis.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the config ConfigMap. */}}
{{- define "aegis.configMapName" -}}
{{- printf "%s-config" (include "aegis.fullname" .) -}}
{{- end -}}

{{/*
Pod-level securityContext (non-root). Shared by all Aegis pods.
*/}}
{{- define "aegis.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
Container-level securityContext. Pass readOnlyRootFilesystem via the dict.
Usage: {{ include "aegis.containerSecurityContext" (dict "readOnlyRootFilesystem" true) }}
*/}}
{{- define "aegis.containerSecurityContext" -}}
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
