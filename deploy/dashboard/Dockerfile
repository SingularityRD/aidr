FROM node:24.12.0-alpine3.23
WORKDIR /app
COPY --chown=node:node public ./public
COPY --chown=node:node auth-templates ./auth-templates
COPY --chown=node:node server.mjs ./server.mjs
COPY --chown=node:node monitoring.mjs ./monitoring.mjs
COPY --chown=node:node saml-config.mjs /saml-config.mjs
USER node
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s CMD node -e "fetch('http://127.0.0.1:8080/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.mjs"]
