# Schema migration (and pg_dump backup) image for the AIDR Helm chart.
# Built by deploy/helm/build-images.mjs, which renders migrate.sql from
# supabase/migrations with the same atomic, checksum-verified plan that
# scripts/deployment-migrate.mjs applies for Compose installs.
# The client major version must be >= the server's (supabase/postgres 17.11).
FROM postgres:17.6-alpine3.22
# age seals backups to the operator's recipients; curl uploads the off-cluster
# copy (backup.encryption / backup.offsite in the chart).
RUN apk add --no-cache age curl
COPY migrate.sql migrations.manifest.json /opt/aidr/
COPY migrations /opt/aidr/migrations
COPY aidr-migrate.sh /usr/local/bin/aidr-migrate
USER 70:70
ENTRYPOINT ["/usr/local/bin/aidr-migrate"]
