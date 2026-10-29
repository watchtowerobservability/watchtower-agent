{{- define "wta.name" -}}{{ printf "%s-agent" .Release.Name | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "wta.sa" -}}{{ if .Values.serviceAccount.name }}{{ .Values.serviceAccount.name }}{{ else }}{{ include "wta.name" . }}{{ end }}{{- end }}
{{- define "wta.labels" -}}
app.kubernetes.io/name: watchtower-agent
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "wta.image" -}}
{{- $i := .Values.image -}}
{{- if $i.digest }}{{ $i.repository }}@{{ $i.digest }}{{ else }}{{ $i.repository }}:{{ default .Chart.AppVersion $i.tag }}{{ end }}
{{- end }}
