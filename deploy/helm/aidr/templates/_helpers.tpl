{{/* ------------------------------------------------------------------ */}}
{{/* Names and labels                                                     */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "aidr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aidr.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Component resource name: aidr.component (dict "root" $ "component" "auth") */}}
{{- define "aidr.component" -}}
{{- printf "%s-%s" (include "aidr.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aidr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aidr.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aidr.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "aidr.labels" -}}
helm.sh/chart: {{ include "aidr.chart" .root }}
{{ include "aidr.selectorLabels" . }}
app.kubernetes.io/part-of: aidr
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{- with .root.Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "aidr.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "aidr.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Required inputs                                                      */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "aidr.httpsOrigin" -}}
{{- $value := required (printf "%s is required (an https:// origin)" .name) .value -}}
{{- if not (regexMatch "^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$" $value) -}}
{{- fail (printf "%s must be an https:// origin without credentials, path or trailing slash (got %q)" .name $value) -}}
{{- end -}}
{{- $value -}}
{{- end -}}

{{- define "aidr.dashboardUrl" -}}
{{- include "aidr.httpsOrigin" (dict "name" "publicUrls.dashboard" "value" .Values.publicUrls.dashboard) -}}
{{- end -}}

{{- define "aidr.apiUrl" -}}
{{- include "aidr.httpsOrigin" (dict "name" "publicUrls.api" "value" .Values.publicUrls.api) -}}
{{- end -}}

{{- define "aidr.hostOf" -}}
{{- regexReplaceAll "^https://([^:/]+)(:[0-9]+)?$" . "${1}" -}}
{{- end -}}

{{- define "aidr.secretName" -}}
{{- required "secrets.existingSecret is required: create the platform Secret first (node deploy/helm/generate-secrets.mjs). The chart never generates credentials." .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "aidr.functionsSecretName" -}}
{{- required "secrets.functionsExistingSecret is required: create the edge-functions Secret first (node deploy/helm/generate-secrets.mjs). The chart never generates signing keys." .Values.secrets.functionsExistingSecret -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Images                                                               */}}
{{/* aidr.image (dict "root" $ "image" .Values.x.image "name" "x.image" "defaultTag" true) */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "aidr.image" -}}
{{- $image := .image -}}
{{- $registry := default $image.registry .root.Values.global.imageRegistry -}}
{{- if not $registry -}}
{{- fail (printf "%s: no registry. Build and push the AIDR images (node deploy/helm/build-images.mjs --registry <registry> --push) and set global.imageRegistry or %s.registry" .name .name) -}}
{{- end -}}
{{- $tag := $image.tag | toString -}}
{{- if and (not $tag) .defaultTag -}}
{{- $tag = .root.Chart.AppVersion -}}
{{- end -}}
{{- if not $tag -}}
{{- fail (printf "%s.tag is required" .name) -}}
{{- end -}}
{{- if eq $tag "latest" -}}
{{- fail (printf "%s.tag must be an immutable version, not \"latest\"" .name) -}}
{{- end -}}
{{- if $image.digest -}}
{{- printf "%s/%s:%s@%s" $registry $image.repository $tag $image.digest -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry $image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "aidr.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range . }}
{{- if kindIs "string" . }}
  - name: {{ . }}
{{- else }}
  - {{ toYaml . | nindent 4 | trim }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Security contexts                                                    */}}
{{/* aidr.podSecurityContext (dict "root" $ "runAsUser" 1000 "fsGroup" 1000) */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "aidr.podSecurityContext" -}}
{{- $ctx := deepCopy .root.Values.podSecurityContext -}}
{{- $_ := set $ctx "runAsNonRoot" true -}}
{{- if .runAsUser -}}
{{- $_ := set $ctx "runAsUser" (int .runAsUser) -}}
{{- $_ := set $ctx "runAsGroup" (int (default .runAsUser .runAsGroup)) -}}
{{- end -}}
{{- if .fsGroup -}}
{{- $_ := set $ctx "fsGroup" (int .fsGroup) -}}
{{- end -}}
{{- with .supplementalGroups -}}
{{- $groups := list -}}
{{- range . }}{{ $groups = append $groups (int .) }}{{ end -}}
{{- $_ := set $ctx "supplementalGroups" $groups -}}
{{- end -}}
{{- if not (hasKey $ctx "seccompProfile") -}}
{{- $_ := set $ctx "seccompProfile" (dict "type" "RuntimeDefault") -}}
{{- end -}}
securityContext:
  {{- toYaml $ctx | nindent 2 }}
{{- end -}}

{{/* aidr.containerSecurityContext (dict "root" $ "readOnlyRootFilesystem" true) */}}
{{- define "aidr.containerSecurityContext" -}}
{{- $ctx := deepCopy .root.Values.containerSecurityContext -}}
{{- $_ := set $ctx "allowPrivilegeEscalation" false -}}
{{- $_ := set $ctx "runAsNonRoot" true -}}
{{- $_ := set $ctx "capabilities" (dict "drop" (list "ALL")) -}}
{{- if hasKey . "readOnlyRootFilesystem" -}}
{{- $_ := set $ctx "readOnlyRootFilesystem" .readOnlyRootFilesystem -}}
{{- end -}}
securityContext:
  {{- toYaml $ctx | nindent 2 }}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Resource presets                                                     */}}
{{/* small is the base; medium doubles and large quadruples it.           */}}
{{/* cpu in millicores, memory in MiB.                                    */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "aidr.resourceBase" -}}
dashboard:      {req: {cpu: 100, mem: 128}, lim: {cpu: 500,  mem: 256}}
apiGateway:     {req: {cpu: 100, mem: 128}, lim: {cpu: 1000, mem: 256}}
auth:           {req: {cpu: 50,  mem: 64},  lim: {cpu: 500,  mem: 256}}
rest:           {req: {cpu: 50,  mem: 64},  lim: {cpu: 500,  mem: 256}}
storage:        {req: {cpu: 50,  mem: 128}, lim: {cpu: 500,  mem: 512}}
functions:      {req: {cpu: 250, mem: 512}, lim: {cpu: 2000, mem: 1024}}
postgresql:     {req: {cpu: 250, mem: 1024}, lim: {cpu: 2000, mem: 2048}}
migrations:     {req: {cpu: 100, mem: 128}, lim: {cpu: 500,  mem: 256}}
backup:         {req: {cpu: 100, mem: 128}, lim: {cpu: 1000, mem: 512}}
notificationDispatch: {req: {cpu: 50, mem: 64}, lim: {cpu: 500, mem: 256}}
postureScannerServer: {req: {cpu: 500, mem: 512}, lim: {cpu: 2000, mem: 2048}}
postureScannerAgent:  {req: {cpu: 1000, mem: 1024}, lim: {cpu: 4000, mem: 4096}}
postureScannerBridge: {req: {cpu: 250, mem: 128}, lim: {cpu: 1000, mem: 512}}
privacyGateway:       {req: {cpu: 500, mem: 2048}, lim: {cpu: 2000, mem: 4096}}
{{- end -}}

{{/* aidr.resources (dict "root" $ "component" "auth" "override" .Values.auth.resources) */}}
{{- define "aidr.resources" -}}
{{- if .override -}}
resources:
  {{- toYaml .override | nindent 2 }}
{{- else -}}
{{- $preset := .root.Values.resourcesPreset -}}
{{- $factor := dict "small" 1 "medium" 2 "large" 4 -}}
{{- if not (hasKey $factor $preset) -}}
{{- fail (printf "resourcesPreset must be small, medium or large (got %q)" $preset) -}}
{{- end -}}
{{- $f := int (get $factor $preset) -}}
{{- $base := get (include "aidr.resourceBase" . | fromYaml) .component -}}
{{- if not $base -}}
{{- fail (printf "no resource preset for component %q" .component) -}}
{{- end -}}
resources:
  requests:
    cpu: {{ mul (int $base.req.cpu) $f }}m
    memory: {{ mul (int $base.req.mem) $f }}Mi
  limits:
    cpu: {{ mul (int $base.lim.cpu) $f }}m
    memory: {{ mul (int $base.lim.mem) $f }}Mi
{{- end -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Database connection                                                  */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "aidr.dbHost" -}}
{{- if .Values.postgresql.enabled -}}
{{- include "aidr.component" (dict "root" . "component" "db") -}}
{{- else -}}
{{- required "externalDatabase.host is required when postgresql.enabled=false" .Values.externalDatabase.host -}}
{{- end -}}
{{- end -}}

{{- define "aidr.dbPort" -}}
{{- if .Values.postgresql.enabled -}}5432{{- else -}}{{ .Values.externalDatabase.port }}{{- end -}}
{{- end -}}

{{- define "aidr.dbName" -}}
{{- if .Values.postgresql.enabled -}}postgres{{- else -}}{{ .Values.externalDatabase.database }}{{- end -}}
{{- end -}}

{{- define "aidr.dbSslMode" -}}
{{- if .Values.postgresql.enabled -}}disable{{- else -}}{{ .Values.externalDatabase.sslMode }}{{- end -}}
{{- end -}}

{{/* postgres://<user>:$(POSTGRES_PASSWORD)@host:port/db?sslmode=... (password expanded by the kubelet) */}}
{{- define "aidr.dbUrl" -}}
{{- printf "%s://%s:$(POSTGRES_PASSWORD)@%s:%s/%s?sslmode=%s" (default "postgres" .scheme) .user (include "aidr.dbHost" .root) (include "aidr.dbPort" .root) (include "aidr.dbName" .root) (include "aidr.dbSslMode" .root) -}}
{{- end -}}

{{- define "aidr.postgresPasswordEnv" -}}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "aidr.secretName" . }}
      key: postgres-password
{{- end -}}

{{- define "aidr.secretEnv" -}}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ include "aidr.secretName" .root }}
      key: {{ .key }}
{{- end -}}

{{/* In-cluster service URLs */}}
{{- define "aidr.gatewayUrl" -}}
{{- printf "http://%s:8000" (include "aidr.component" (dict "root" . "component" "api-gw")) -}}
{{- end -}}

{{/* PodDisruptionBudget and optional HorizontalPodAutoscaler for a Deployment */}}
{{- define "aidr.pdbAndHpa" -}}
{{- $name := include "aidr.component" (dict "root" .root "component" .component) -}}
{{- $autoscaling := default (dict "enabled" false) .values.autoscaling -}}
{{- if and .values.pdb .values.pdb.enabled (or $autoscaling.enabled (gt (int .values.replicaCount) 1)) }}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ $name }}
  labels:
    {{- include "aidr.labels" (dict "root" .root "component" .component) | nindent 4 }}
spec:
  minAvailable: {{ .values.pdb.minAvailable }}
  selector:
    matchLabels:
      {{- include "aidr.selectorLabels" (dict "root" .root "component" .component) | nindent 6 }}
{{- end }}
{{- if $autoscaling.enabled }}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ $name }}
  labels:
    {{- include "aidr.labels" (dict "root" .root "component" .component) | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ $name }}
  minReplicas: {{ $autoscaling.minReplicas }}
  maxReplicas: {{ $autoscaling.maxReplicas }}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ $autoscaling.targetCPUUtilizationPercentage }}
{{- end }}
{{- end -}}

{{/* Standard pod-level fields shared by every workload */}}
{{- define "aidr.podCommon" -}}
serviceAccountName: {{ include "aidr.serviceAccountName" .root }}
automountServiceAccountToken: false
{{- include "aidr.imagePullSecrets" .root }}
{{- with .values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Privacy gateway (optional): validation and rendered service JSON    */}}
{{/* The layout matches deploy/privacy-gateway/privacy-gateway.mjs and   */}}
{{/* packages/privacy/deployment/container-service-config.mjs.           */}}
{{/* ------------------------------------------------------------------ */}}
{{/* aidr.privacyGateway.cidrs (dict "name" "privacyGateway.egress.cidrs" "cidrs" list) */}}
{{- define "aidr.privacyGateway.cidrs" -}}
{{- $name := .name -}}
{{- range .cidrs -}}
{{- $cidr := toString . -}}
{{- if not (regexMatch "^[0-9a-fA-F:.]+/[0-9]{1,3}$" $cidr) -}}
{{- fail (printf "%s: %q is not a CIDR" $name $cidr) -}}
{{- end -}}
{{- $prefix := atoi (last (splitList "/" $cidr)) -}}
{{- $minimum := ternary 16 8 (contains ":" $cidr) -}}
{{- if lt $prefix $minimum -}}
{{- fail (printf "%s: %s is too broad; the allow-list must name destinations (no default route, prefix /%d or longer)" $name $cidr $minimum) -}}
{{- end -}}
{{- if regexMatch "^(0\\.|127\\.|169\\.254\\.|::1/|fe80:)" $cidr -}}
{{- fail (printf "%s: %s is a loopback, link-local or reserved range" $name $cidr) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* aidr.privacyGateway.trustPath (dict "name" "oidc.caPath" "value" path) */}}
{{- define "aidr.privacyGateway.trustPath" -}}
{{- if not (regexMatch "^/etc/aidr-privacy/trust/[A-Za-z0-9][A-Za-z0-9._-]*$" (toString .value)) -}}
{{- fail (printf "privacyGateway.serviceConfig.%s must be /etc/aidr-privacy/trust/<key of privacyGateway.trustConfigMap> (got %q)" .name (toString .value)) -}}
{{- end -}}
{{- end -}}

{{/* Refuses weak or incomplete gateway configuration; renders nothing. */}}
{{- define "aidr.privacyGateway.validate" -}}
{{- $pg := .Values.privacyGateway -}}
{{- if not $pg.mtls.enabled -}}
{{- fail "privacyGateway.mtls.enabled=false is refused: the privacy gateway only serves mutually authenticated TLS (every POST /v1/egress needs an enrolled client certificate)" -}}
{{- end -}}
{{- $_ := required "privacyGateway.mtls.existingSecret is required when privacyGateway.enabled: a Secret with tls.crt, tls.key and ca.crt (mutual TLS is mandatory)" $pg.mtls.existingSecret -}}
{{- $_ := required "privacyGateway.existingSecret is required when privacyGateway.enabled: a Secret whose keys are the serviceConfig *Ref names" $pg.existingSecret -}}
{{- $_ := required "privacyGateway.trustConfigMap is required when privacyGateway.enabled: a ConfigMap with the IdP/broker CAs, broker certificate and signed policy" $pg.trustConfigMap -}}
{{- $_ := required "privacyGateway.models.existingClaim is required when privacyGateway.enabled: a PVC holding the independently approved NER model" $pg.models.existingClaim -}}
{{- if empty $pg.egress.cidrs -}}
{{- fail "privacyGateway.egress.cidrs is required when privacyGateway.enabled: list the provider, identity provider and broker CIDRs (TCP 443); unrestricted egress is refused" -}}
{{- end -}}
{{- include "aidr.privacyGateway.cidrs" (dict "name" "privacyGateway.egress.cidrs" "cidrs" $pg.egress.cidrs) -}}
{{- include "aidr.privacyGateway.cidrs" (dict "name" "privacyGateway.clientCIDRs" "cidrs" $pg.clientCIDRs) -}}
{{- if and (ne $pg.service.type "ClusterIP") (empty $pg.clientCIDRs) -}}
{{- fail (printf "privacyGateway.service.type=%s exposes the gateway outside the cluster; list the allowed client ranges in privacyGateway.clientCIDRs" $pg.service.type) -}}
{{- end -}}
{{- $cfg := $pg.serviceConfig -}}
{{- range $key := list "tls" "host" "port" "secretStore" "databasePath" "documents" -}}
{{- if hasKey $cfg $key -}}
{{- fail (printf "privacyGateway.serviceConfig.%s must not be set: the chart owns the listener, mutual TLS, secret store and state path, and document parsing is not packaged in the gateway image" $key) -}}
{{- end -}}
{{- end -}}
{{- if contains "REPLACE" (toJson $cfg) -}}
{{- fail "privacyGateway.serviceConfig still holds a REPLACE placeholder; supply the approved values" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" (toString (required "privacyGateway.serviceConfig.tenantId is required" $cfg.tenantId))) -}}
{{- fail "privacyGateway.serviceConfig.tenantId must be a short identifier" -}}
{{- end -}}
{{- $dest := required "privacyGateway.serviceConfig.destination is required" $cfg.destination -}}
{{- $origins := dict "openai-responses" "https://api.openai.com" "gemini-generate-content" "https://generativelanguage.googleapis.com" -}}
{{- if or (not (hasKey $origins (toString $dest.kind))) (ne (toString $dest.origin) (get $origins (toString $dest.kind))) -}}
{{- fail "privacyGateway.serviceConfig.destination must be openai-responses (https://api.openai.com) or gemini-generate-content (https://generativelanguage.googleapis.com)" -}}
{{- end -}}
{{- $_ := required "privacyGateway.serviceConfig.destination.model is required (the institution-approved model)" $dest.model -}}
{{- $_ := required "privacyGateway.serviceConfig.destination.secretRef is required" $dest.secretRef -}}
{{- $oidc := required "privacyGateway.serviceConfig.oidc is required" $cfg.oidc -}}
{{- $broker := required "privacyGateway.serviceConfig.broker is required" $cfg.broker -}}
{{- range $pair := list (list "oidc.issuer" $oidc.issuer) (list "broker.issuer" $broker.issuer) -}}
{{- if not (regexMatch "^https://[^/@\\s]+" (toString (index $pair 1))) -}}
{{- fail (printf "privacyGateway.serviceConfig.%s must be an https:// URL" (index $pair 0)) -}}
{{- end -}}
{{- end -}}
{{- $ner := required "privacyGateway.serviceConfig.ner is required" $cfg.ner -}}
{{- if hasKey $ner "python" -}}
{{- fail "privacyGateway.serviceConfig.ner.python must not be set: the image owns the NER runtime" -}}
{{- end -}}
{{- if or (not (hasPrefix "/opt/aidr-models/" (toString $ner.manifest))) (contains ".." (toString $ner.manifest)) -}}
{{- fail "privacyGateway.serviceConfig.ner.manifest must be a path under /opt/aidr-models (privacyGateway.models.existingClaim)" -}}
{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" (toString $ner.manifestSha256)) -}}
{{- fail "privacyGateway.serviceConfig.ner.manifestSha256 must be the independently approved 64-hex manifest digest" -}}
{{- end -}}
{{- include "aidr.privacyGateway.trustPath" (dict "name" "oidc.caPath" "value" $oidc.caPath) -}}
{{- include "aidr.privacyGateway.trustPath" (dict "name" "broker.caPath" "value" $broker.caPath) -}}
{{- include "aidr.privacyGateway.trustPath" (dict "name" "broker.certPath" "value" $broker.certPath) -}}
{{- $policy := required "privacyGateway.serviceConfig.policy is required" $cfg.policy -}}
{{- include "aidr.privacyGateway.trustPath" (dict "name" "policy.signedPath" "value" $policy.signedPath) -}}
{{- if empty $policy.keys -}}
{{- fail "privacyGateway.serviceConfig.policy.keys must list the policy verification keys" -}}
{{- end -}}
{{- range $policy.keys -}}
{{- include "aidr.privacyGateway.trustPath" (dict "name" "policy.keys[].path" "value" .path) -}}
{{- end -}}
{{- end -}}

{{/* The service JSON: operator settings plus the chart-owned listener, TLS, secret store, state and NER runtime. */}}
{{- define "aidr.privacyGateway.serviceConfig" -}}
{{- $cfg := deepCopy .Values.privacyGateway.serviceConfig -}}
{{- $ner := deepCopy $cfg.ner -}}
{{- $_ := set $ner "python" "/opt/aidr-ner/bin/python3" -}}
{{- $_ := set $cfg "ner" $ner -}}
{{- $_ := set $cfg "secretStore" "mounted-files" -}}
{{- $_ := set $cfg "host" "0.0.0.0" -}}
{{- $_ := set $cfg "port" 8443 -}}
{{- $_ := set $cfg "databasePath" "/var/lib/aidr-privacy/control.sqlite" -}}
{{- $_ := set $cfg "tls" (dict "certPath" "/etc/aidr-privacy/tls/server.pem" "clientCaPath" "/etc/aidr-privacy/tls/client-ca.pem" "keyRef" "aidr-privacy-tls-key") -}}
{{- toPrettyJson $cfg -}}
{{- end -}}
