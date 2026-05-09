{{- define "recklock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "recklock.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "recklock.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "recklock.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{ include "recklock.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "recklock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "recklock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
