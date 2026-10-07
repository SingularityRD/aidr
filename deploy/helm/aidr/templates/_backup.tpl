{{/* ------------------------------------------------------------------ */}}
{{/* Backups: validation plus the pod spec shared by the nightly CronJob */}}
{{/* (backup-cronjob.yaml) and the pre-upgrade hook Job                  */}}
{{/* (backup-pre-upgrade-job.yaml), so both take the same backup.        */}}
{{/* ------------------------------------------------------------------ */}}

{{/*
aidr.backup.validate: fail rendering instead of producing an install whose
backups silently miss data or whose upgrades migrate the schema without one.
*/}}
{{- define "aidr.backup.validate" -}}
{{- $backup := .Values.backup -}}
{{- $storage := .Values.storage -}}
{{- $storageBackup := $backup.storage.enabled -}}
{{- if and $storageBackup (ne $storage.backend "file") -}}
{{- fail "backup.storage.enabled archives the storage.backend=file volume; with storage.backend=s3 protect the bucket with versioning/replication instead and set backup.storage.enabled=false" -}}
{{- end -}}
{{- if and $backup.enabled (eq $storage.backend "file") (not $storageBackup) (not $backup.storage.acknowledgeNotBackedUp) -}}
{{- fail "backup.enabled with storage.backend=file does not cover stored objects: set backup.storage.enabled=true (archive the storage volume), use storage.backend=s3, or set backup.storage.acknowledgeNotBackedUp=true to accept that a restore loses every stored object (dev only)" -}}
{{- end -}}
{{- if and $backup.enabled $storageBackup (has "ReadWriteOncePod" $storage.persistence.accessModes) -}}
{{- fail "backup.storage.enabled cannot mount a ReadWriteOncePod storage volume from the backup pod; use ReadWriteOnce (backup is scheduled next to the storage pod) or ReadWriteMany" -}}
{{- end -}}
{{- if and .Release.IsUpgrade .Values.migrations.enabled (not (and $backup.enabled $backup.preUpgrade.enabled)) (not .Values.migrations.allowWithoutBackup) -}}
{{- fail "refusing to upgrade: the pre-upgrade migrations hook would change the schema without a fresh backup. Enable backup.enabled and backup.preUpgrade.enabled, or set migrations.allowWithoutBackup=true after taking your own backup (e.g. a provider snapshot)" -}}
{{- end -}}
{{- end -}}

{{/*
aidr.backup.podSpec (dict "root" $ "suffix" "")
Backup pod: pg_dump (always) then, with backup.storage.enabled, a tar.gz of the
file storage volume mounted read-only. Each artifact is written as *.partial,
checksummed (SHA-256 sidecar) and only then renamed, so a file without the
.partial suffix is complete. "suffix" tags the file names (e.g. "-pre-upgrade").
*/}}
{{- define "aidr.backup.podSpec" -}}
{{- $root := .root -}}
{{- $values := $root.Values.backup -}}
{{- $name := include "aidr.component" (dict "root" $root "component" "backup") -}}
{{- $storageBackup := and $values.storage.enabled (eq $root.Values.storage.backend "file") -}}
{{- $storageName := include "aidr.component" (dict "root" $root "component" "storage") -}}
{{- $common := dict -}}
{{- if and $storageBackup (not (has "ReadWriteMany" $root.Values.storage.persistence.accessModes)) -}}
{{- /* A ReadWriteOnce volume can only be mounted on the node that already has it attached: run next to the storage pod. */ -}}
{{- $selector := dict "matchLabels" (fromYaml (include "aidr.selectorLabels" (dict "root" $root "component" "storage"))) -}}
{{- $term := dict "labelSelector" $selector "topologyKey" "kubernetes.io/hostname" -}}
{{- $_ := set $common "affinity" (dict "podAffinity" (dict "requiredDuringSchedulingIgnoredDuringExecution" (list $term))) -}}
{{- end -}}
restartPolicy: Never
{{ include "aidr.podCommon" (dict "root" $root "values" $common) }}
{{- if $storageBackup }}
{{ include "aidr.podSecurityContext" (dict "root" $root "runAsUser" $values.runAsUser "fsGroup" $values.runAsUser "supplementalGroups" (list $root.Values.storage.runAsUser)) }}
{{- else }}
{{ include "aidr.podSecurityContext" (dict "root" $root "runAsUser" $values.runAsUser "fsGroup" $values.runAsUser) }}
{{- end }}
containers:
  - name: pg-dump
    image: {{ include "aidr.image" (dict "root" $root "image" $values.image "name" "backup.image" "defaultTag" true) }}
    imagePullPolicy: {{ $values.image.pullPolicy }}
    command:
      - /bin/sh
      - -ec
      - |
        umask 077
        cd /backups
        base="aidr-$(date -u +%Y%m%dT%H%M%SZ){{ default "" .suffix }}"
        # 1. Database (logical, custom format).
        pg_dump --format=custom --no-owner --file="${base}.dump.partial"
        sha256sum "${base}.dump.partial" | sed 's/\.partial$//' > "${base}.dump.sha256"
        mv "${base}.dump.partial" "${base}.dump"
        echo "database backup written: ${base}.dump"
        {{- if $storageBackup }}
        # 2. Stored objects (storage.backend=file), taken after the dump so an
        #    upload racing the backup leaves an orphan file, not a dangling row.
        #    GNU tar keeps storage-api's user.* xattrs (content-type,
        #    cache-control); busybox tar cannot and the manifest records it.
        #    lost+found is root-only filesystem metadata, not an object.
        xattrs=not-preserved
        if tar --version 2>/dev/null | grep -q 'GNU tar'; then
          xattrs=preserved
          tar --xattrs --xattrs-include='user.*' --exclude=./lost+found -C /storage-data -czf "${base}.storage.tar.gz.partial" .
        else
          echo "warning: GNU tar not found; storage extended attributes are not archived" >&2
          tar --exclude=./lost+found -C /storage-data -czf "${base}.storage.tar.gz.partial" .
        fi
        tar -tzf "${base}.storage.tar.gz.partial" > /dev/null
        sha256sum "${base}.storage.tar.gz.partial" | sed 's/\.partial$//' > "${base}.storage.tar.gz.sha256"
        printf 'database=%s\nstorage=%s\nstorage_xattrs=%s\n' "${base}.dump" "${base}.storage.tar.gz" "${xattrs}" > "${base}.manifest"
        mv "${base}.storage.tar.gz.partial" "${base}.storage.tar.gz"
        echo "storage backup written: ${base}.storage.tar.gz (xattrs ${xattrs})"
        {{- end }}
        find /backups -maxdepth 1 -name 'aidr-*' -type f -mtime +{{ int $values.retentionDays }} -delete
    {{- include "aidr.containerSecurityContext" (dict "root" $root) | nindent 4 }}
    env:
      {{- include "aidr.postgresPasswordEnv" $root | nindent 6 }}
      - name: PGPASSWORD
        value: $(POSTGRES_PASSWORD)
      - name: PGHOST
        value: {{ include "aidr.dbHost" $root | quote }}
      - name: PGPORT
        value: {{ include "aidr.dbPort" $root | quote }}
      - name: PGDATABASE
        value: {{ include "aidr.dbName" $root | quote }}
      - name: PGUSER
        value: postgres
      - name: PGSSLMODE
        value: {{ include "aidr.dbSslMode" $root | quote }}
    {{- include "aidr.resources" (dict "root" $root "component" "backup" "override" $values.resources) | nindent 4 }}
    volumeMounts:
      - name: backups
        mountPath: /backups
      - name: tmp
        mountPath: /tmp
      {{- if $storageBackup }}
      - name: storage-data
        mountPath: /storage-data
        readOnly: true
      {{- end }}
volumes:
  - name: backups
    persistentVolumeClaim:
      claimName: {{ default $name $values.persistence.existingClaim }}
  - name: tmp
    emptyDir:
      sizeLimit: 64Mi
  {{- if $storageBackup }}
  - name: storage-data
    persistentVolumeClaim:
      claimName: {{ default $storageName $root.Values.storage.persistence.existingClaim }}
      readOnly: true
  {{- end }}
{{- end -}}
