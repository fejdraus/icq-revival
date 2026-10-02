# The services that run around the IM server, one build target each:
#
#   register     registration, profile, password and e-mail pages
#   admin        admin panel over the management API
#   legacy-web   pages in place of the ICQ.com services the clients still open
#   backup       the daily database copy
#
# Built from the repository root, since every service also takes files from
# deploy/shared and one takes the code lists that live with the register:
#
#   docker build -f deploy/docker/services.Dockerfile --target register .
#
# None of them has npm dependencies - they use Node's standard library only,
# node:sqlite included, which needs Node 22.5 or later.

FROM node:24-slim AS base
WORKDIR /app
ENV NODE_ENV=production
# node:sqlite still prints an experimental warning on every start.
ENV NODE_NO_WARNINGS=1


FROM base AS register
COPY --chown=node deploy/oscar-register/ ./
COPY --chown=node deploy/shared/ui.js deploy/shared/flower.png deploy/shared/logo-page.png ./
USER node
EXPOSE 8099
CMD ["node", "server.js"]


FROM base AS admin
COPY --chown=node deploy/oscar-admin/ ./
COPY --chown=node deploy/shared/ui.js deploy/shared/flower.png deploy/shared/logo-page.png ./
USER node
EXPOSE 8100
CMD ["node", "server.js"]


FROM base AS legacy-web
# Pillow shrinks the pictures people upload as their buddy icon.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pil \
 && rm -rf /var/lib/apt/lists/*
COPY --chown=node deploy/oscar-legacy-web/ ./
COPY --chown=node deploy/shared/ui.js deploy/shared/flower.png deploy/shared/logo-page.png ./
# The white pages show countries and interests by name, from the same lists
# the registration pages use.
COPY --chown=node deploy/oscar-register/icq-codes.json ./
USER node
EXPOSE 8101
CMD ["node", "server.js"]


FROM base AS backup
# age encrypts the copies to the operator's public keys (BACKUP_AGE_RECIPIENTS
# in .env); Debian packages it for amd64 and arm64 alike.
RUN apt-get update \
 && apt-get install -y --no-install-recommends age \
 && rm -rf /var/lib/apt/lists/*
COPY --chown=node deploy/scripts/oscar-backup.sh /usr/local/bin/oscar-backup.sh
RUN chmod 755 /usr/local/bin/oscar-backup.sh
USER node
# Once a day, the first run right away.
CMD ["sh", "-c", "while true; do /usr/local/bin/oscar-backup.sh; sleep 86400; done"]
