# Edge functions runtime image for the AIDR Helm chart.
# Built by deploy/helm/build-images.mjs from a staged context holding the
# reviewed upstream functions router (docker/volumes/functions/main) and the
# AIDR functions in supabase/functions. Never build it from an unstaged tree.
FROM supabase/edge-runtime:v1.76.2
COPY functions /home/deno/functions
# The chart runs every container as a non-root user on a read-only root
# filesystem; the Deno module cache lives on the /tmp emptyDir.
ENV HOME=/tmp \
    DENO_DIR=/tmp/deno-cache
USER 1000:1000
EXPOSE 9000
CMD ["start", "--main-service", "/home/deno/functions/main"]
