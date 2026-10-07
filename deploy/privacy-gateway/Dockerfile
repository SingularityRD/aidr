# AIDR privacy gateway (aidr-privacy-service) container image.
#
# Built from a STAGED context, never from the source tree:
#   scripts/deployment-prepare.mjs --with-privacy-gateway  (Compose: <install>/privacy-gateway/image)
#   deploy/helm/build-images.mjs --privacy-gateway         (Kubernetes)
# Both call deploy/privacy-gateway/stage-image.mjs, which copies only the compiled
# privacy package, the offline NER worker and its hash-pinned wheel lock.
#
# Hardening contract (checked by scripts/deployment-prepare.test.mjs and
# deploy/helm/chart.test.mjs): digest-pinned bases, numeric non-root user, no
# package manager or shell use at runtime, a root filesystem that works read-only
# (state, model and secret paths are mounts; /tmp is the only scratch space) and a
# HEALTHCHECK. The runtime inherits nothing from the build stage except the venv.

# Node runtime is copied from the official image; both stages are Debian bookworm
# (glibc 2.36), the platform the Linux NER wheel lock was measured on.
FROM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS node

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS ner
COPY package/ner/requirements.linux-py311.lock.txt /tmp/requirements.lock.txt
COPY wheelhouse/ /tmp/wheelhouse/
# Every wheel is hash-checked against the lock. An air-gapped build stages the
# wheelhouse beforehand (see deploy/privacy-gateway/README.md) and installs with
# --no-index; a connected build downloads the same hashes.
RUN python -m venv /opt/aidr-ner \
 && if ls /tmp/wheelhouse/*.whl >/dev/null 2>&1; then \
      /opt/aidr-ner/bin/pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: --no-index --find-links /tmp/wheelhouse -r /tmp/requirements.lock.txt; \
    else \
      /opt/aidr-ner/bin/pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: --extra-index-url https://download.pytorch.org/whl/cpu -r /tmp/requirements.lock.txt; \
    fi \
 && /opt/aidr-ner/bin/python -m pip uninstall --yes pip \
 && find /opt/aidr-ner -name '__pycache__' -type d -prune -exec rm -rf {} +

FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=ner /opt/aidr-ner /opt/aidr-ner
RUN groupadd --system --gid 10001 aidr-privacy \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin aidr-privacy \
 && mkdir -p /etc/aidr-privacy/config /etc/aidr-privacy/trust /etc/aidr-privacy/tls /run/secrets/aidr-privacy /opt/aidr-models /var/lib/aidr-privacy \
 && chown 10001:10001 /var/lib/aidr-privacy && chmod 0700 /var/lib/aidr-privacy \
 && rm -rf /var/lib/apt/lists/* /root/.cache
# Application files stay root-owned and read-only to the service user.
COPY --chown=root:root --chmod=0755 package /opt/aidr-private/node_modules/@singularityrd/aidr-privacy
COPY --chown=root:root --chmod=0644 healthcheck.mjs /opt/aidr-private/healthcheck.mjs
ENV NODE_ENV=production \
    AIDR_PRIVACY_CONFIG=/etc/aidr-privacy/config/service.json \
    HOME=/tmp \
    HF_HOME=/tmp/hf \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1
USER 10001:10001
WORKDIR /opt/aidr-private
VOLUME ["/var/lib/aidr-privacy"]
EXPOSE 8443
STOPSIGNAL SIGTERM
# The mTLS listener opens only after the NER model, policy, identity broker and
# durable state are ready (startTextService listens last), so an accepted TCP
# connection is the readiness signal. The probe never presents a client
# certificate and never sends a request.
HEALTHCHECK --interval=30s --timeout=5s --start-period=300s --retries=3 CMD ["/usr/local/bin/node", "/opt/aidr-private/healthcheck.mjs"]
ENTRYPOINT ["/usr/local/bin/node", "/opt/aidr-private/node_modules/@singularityrd/aidr-privacy/dist/platform/serve.js", "--config", "/opt/aidr-private/node_modules/@singularityrd/aidr-privacy/deployment/container-service-config.mjs"]
