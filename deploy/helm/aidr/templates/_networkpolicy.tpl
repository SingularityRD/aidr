{{/* NetworkPolicy peer and egress-rule helpers */}}
{{- define "aidr.np.peer" -}}
- podSelector:
    matchLabels:
      {{- include "aidr.selectorLabels" (dict "root" .root "component" .component) | nindent 6 }}
{{- end -}}
{{- define "aidr.np.db" -}}
{{- if .Values.postgresql.enabled }}
- to:
    {{- include "aidr.np.peer" (dict "root" . "component" "db") | nindent 4 }}
  ports:
    - port: 5432
      protocol: TCP
{{- else }}
- to:
    {{- range .Values.externalDatabase.networkPolicyCIDRs }}
    - ipBlock:
        cidr: {{ . }}
    {{- end }}
  ports:
    - port: {{ int .Values.externalDatabase.port }}
      protocol: TCP
{{- end }}
{{- end -}}
{{- define "aidr.np.cidrs" -}}
{{- if .cidrs }}
- to:
    {{- range .cidrs }}
    - ipBlock:
        cidr: {{ . }}
    {{- end }}
  ports:
    - port: {{ int .port }}
      protocol: TCP
{{- end }}
{{- end -}}
{{- define "aidr.np.ingressController" -}}
- namespaceSelector:
    {{- toYaml .Values.networkPolicy.ingressControllerNamespaceSelector | nindent 4 }}
  {{- with .Values.networkPolicy.ingressControllerPodSelector }}
  podSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end -}}
