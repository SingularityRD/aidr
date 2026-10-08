FROM node:26.10.0-alpine3.24@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80
# This runner executes only Node; package managers are not runtime dependencies.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
COPY --chown=node:node public ./public
COPY --chown=node:node auth-templates ./auth-templates
COPY --chown=node:node server.mjs ./server.mjs
COPY --chown=node:node monitoring.mjs ./monitoring.mjs
COPY --chown=node:node release-manifest.mjs ./release-manifest.mjs
COPY --chown=node:node security-headers.mjs ./security-headers.mjs
COPY --chown=node:node saml-config.mjs /saml-config.mjs
USER node
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s CMD node -e "fetch('http://127.0.0.1:8080/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.mjs"]
