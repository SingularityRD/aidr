# Schema migration (and pg_dump backup) image for the AIDR Helm chart.
# Built by deploy/helm/build-images.mjs, which renders migrate.sql from
# supabase/migrations with the same atomic, checksum-verified plan that
# scripts/deployment-migrate.mjs applies for Compose installs.
# The client must be >= the server (supabase/postgres 17.11), so the base is the
# 17.11 client, pinned by digest like every other first-party image base.
FROM postgres:17.11-alpine3.24@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
COPY migrate.sql migrations.manifest.json /opt/aidr/
COPY migrations /opt/aidr/migrations
COPY aidr-migrate.sh /usr/local/bin/aidr-migrate
USER 70:70
ENTRYPOINT ["/usr/local/bin/aidr-migrate"]
