# syntax=docker/dockerfile:1

FROM node:20-alpine AS demo-keys
WORKDIR /build
COPY scripts/generate-demo-keys.js scripts/generate-demo-keys.js
RUN node scripts/generate-demo-keys.js /build/keys

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV SOCKET_PATH=/run/restricted-ssh-agent/agent.sock
ENV USER_KEY_PATH=/app/keys/user_ed25519.pem
ENV JUMP_HOST_PUBLIC_KEY=/app/keys/jump_host_ed25519.pub
ENV TARGET_HOST_PUBLIC_KEY=/app/keys/target_host_ed25519.pub
ENV TARGET_USER=deploy

COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
COPY --from=demo-keys --chown=node:node /build/keys/user_ed25519.pem /app/keys/user_ed25519.pem
COPY --from=demo-keys --chown=node:node /build/keys/jump_host_ed25519.pub /app/keys/jump_host_ed25519.pub
COPY --from=demo-keys --chown=node:node /build/keys/target_host_ed25519.pub /app/keys/target_host_ed25519.pub
RUN chmod 600 /app/keys/user_ed25519.pem && chmod 644 /app/keys/*.pub && \
    mkdir -p /run/restricted-ssh-agent && chown node:node /run/restricted-ssh-agent

USER node
EXPOSE 0
ENTRYPOINT ["node", "src/agent.js"]
