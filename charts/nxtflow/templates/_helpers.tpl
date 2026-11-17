{{/*
Expand the name of the chart.
*/}}
{{- define "nxtflow.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nxtflow.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "nxtflow.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nxtflow.labels" -}}
helm.sh/chart: {{ include "nxtflow.chart" . }}
{{ include "nxtflow.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nxtflow.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nxtflow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Subchart enablement helpers matching Helm v4 tags.standalone + condition precedence.
*/}}
{{- define "nxtflow.lokiBundled" -}}
{{- $b := .Values.bundled | default dict -}}
{{- $c := $b.loki | default dict -}}
{{- if hasKey $c "enabled" -}}
{{- ternary "true" "" $c.enabled -}}
{{- else -}}
{{- ternary "true" "" .Values.tags.standalone -}}
{{- end -}}
{{- end }}

{{- define "nxtflow.prometheusBundled" -}}
{{- $b := .Values.bundled | default dict -}}
{{- $c := $b.prometheus | default dict -}}
{{- if hasKey $c "enabled" -}}
{{- ternary "true" "" $c.enabled -}}
{{- else -}}
{{- ternary "true" "" .Values.tags.standalone -}}
{{- end -}}
{{- end }}

{{- define "nxtflow.grafanaBundled" -}}
{{- $b := .Values.bundled | default dict -}}
{{- $c := $b.grafana | default dict -}}
{{- if hasKey $c "enabled" -}}
{{- ternary "true" "" $c.enabled -}}
{{- else -}}
{{- ternary "true" "" .Values.tags.standalone -}}
{{- end -}}
{{- end }}

{{/*
Effective Loki URL (bundled SingleBinary service or external URL).
*/}}
{{/*
Subchart service names honoring subchart fullname logic when release name includes subchart name.
*/}}
{{- define "nxtflow.bundledLokiService" -}}
{{- $loki := .Values.loki | default dict -}}
{{- if $loki.fullnameOverride -}}
{{- $loki.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default "loki" $loki.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{- define "nxtflow.bundledPrometheusService" -}}
{{- $prom := .Values.prometheus | default dict -}}
{{- $srv := $prom.server | default dict -}}
{{- if $srv.fullnameOverride -}}
{{- $srv.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default "prometheus" $prom.nameOverride -}}
{{- $promFull := "" -}}
{{- if $prom.fullnameOverride -}}
{{- $promFull = $prom.fullnameOverride -}}
{{- else if contains $name .Release.Name -}}
{{- $promFull = .Release.Name -}}
{{- else -}}
{{- $promFull = printf "%s-%s" .Release.Name $name -}}
{{- end -}}
{{- printf "%s-%s" $promFull (default "server" $srv.name) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{- define "nxtflow.bundledGrafanaService" -}}
{{- $graf := .Values.grafana | default dict -}}
{{- if $graf.fullnameOverride -}}
{{- $graf.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default "grafana" $graf.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Effective CA file path for external Loki TLS (defaults to mounted ConfigMap path when existingCaConfigMap is set).
*/}}
{{- define "nxtflow.externalLokiCaFile" -}}
{{- if .Values.externalLoki.tls.caFile -}}
{{- .Values.externalLoki.tls.caFile -}}
{{- else if .Values.externalLoki.tls.existingCaConfigMap -}}
/etc/nxtflow/ca/ca.crt
{{- end -}}
{{- end }}

{{/*
Effective enricher metrics port & listenAddr aligned between Service, containerPort, and enricher.yaml.
*/}}
{{- define "nxtflow.enricherMetricsPort" -}}
{{- $addr := .Values.enricher.metrics.listenAddr | default "0.0.0.0:9090" -}}
{{- if ne $addr "0.0.0.0:9090" -}}
{{- splitList ":" $addr | last -}}
{{- else -}}
{{- .Values.collector.metricsService.enricherPort -}}
{{- end -}}
{{- end }}

{{- define "nxtflow.enricherMetricsListenAddr" -}}
{{- $addr := .Values.enricher.metrics.listenAddr | default "0.0.0.0:9090" -}}
{{- if ne $addr "0.0.0.0:9090" -}}
{{- $addr -}}
{{- else -}}
{{- printf "0.0.0.0:%d" (int .Values.collector.metricsService.enricherPort) -}}
{{- end -}}
{{- end }}

{{- define "nxtflow.enricherHttpPort" -}}
{{- $addr := .Values.enricher.ingest.http.listenAddr | default "0.0.0.0:8081" -}}
{{- splitList ":" $addr | last | default "8081" -}}
{{- end }}

{{- define "nxtflow.lokiUrl" -}}
{{- if include "nxtflow.lokiBundled" . -}}
{{- printf "http://%s:3100" (include "nxtflow.bundledLokiService" .) -}}
{{- else -}}
{{- .Values.externalLoki.url | trimSuffix "/" -}}
{{- end -}}
{{- end }}

{{/*
Whether inline Loki credentials require creating a Secret.
*/}}
{{- define "nxtflow.hasInlineLokiAuth" -}}
{{- if and (empty .Values.externalLoki.auth.existingSecret) (or (not (empty .Values.externalLoki.auth.username)) (not (empty .Values.externalLoki.auth.password)) (not (empty .Values.externalLoki.auth.bearerToken))) -}}
true
{{- end -}}
{{- end }}

{{/*
Secret name for Loki credentials.
*/}}
{{- define "nxtflow.lokiAuthSecretName" -}}
{{- if .Values.externalLoki.auth.existingSecret -}}
{{- .Values.externalLoki.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-loki-auth" (include "nxtflow.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Fail-fast configuration validation guards.
*/}}
{{- define "nxtflow.validateConfig" -}}
{{- $lokiBundled := include "nxtflow.lokiBundled" . -}}
{{- if and $lokiBundled (not (empty .Values.externalLoki.url)) -}}
{{- fail "Invalid configuration: both bundled Loki (standalone) and externalLoki.url are set. Set tags.standalone=false (or bundled.loki.enabled=false) when using externalLoki.url." -}}
{{- end -}}
{{- if and (not $lokiBundled) (empty .Values.externalLoki.url) (ne .Values.enricher.shipper.mode "file") -}}
{{- fail "Invalid configuration: externalLoki.url is required when bundled Loki is disabled (tags.standalone=false) and enricher.shipper.mode != file." -}}
{{- end -}}
{{- if and .Values.mcp.enabled (not $lokiBundled) (empty .Values.externalLoki.url) -}}
{{- fail "Invalid configuration: mcp.enabled=true requires either bundled Loki (tags.standalone=true) or externalLoki.url." -}}
{{- end -}}
{{- if and (eq .Values.collector.goflow2.transport "http") (not .Values.enricher.ingest.http.enabled) -}}
{{- fail "Invalid configuration: collector.goflow2.transport=http requires enricher.ingest.http.enabled=true." -}}
{{- end -}}
{{- if and (eq .Values.collector.goflow2.transport "file") (not .Values.enricher.ingest.file.enabled) -}}
{{- fail "Invalid configuration: collector.goflow2.transport=file requires enricher.ingest.file.enabled=true." -}}
{{- end -}}
{{- if and .Values.mcp.enabled .Values.mcp.ingress.enabled -}}
{{- if empty .Values.mcp.ingress.hosts -}}
{{- fail "Invalid configuration: mcp.ingress.enabled=true requires non-empty mcp.ingress.hosts." -}}
{{- end -}}
{{- range .Values.mcp.ingress.hosts -}}
{{- if or (empty .host) (empty .paths) -}}
{{- fail "Invalid configuration: each entry in mcp.ingress.hosts must specify non-empty host and paths." -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $mAddr := .Values.enricher.metrics.listenAddr | default "0.0.0.0:9090" -}}
{{- if and (ne $mAddr "0.0.0.0:9090") (ne (int .Values.collector.metricsService.enricherPort) 9090) (ne (int (splitList ":" $mAddr | last)) (int .Values.collector.metricsService.enricherPort)) -}}
{{- fail "Invalid configuration: enricher.metrics.listenAddr port conflicts with collector.metricsService.enricherPort." -}}
{{- end -}}
{{- end }}
