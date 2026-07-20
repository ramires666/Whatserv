FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY src ./src
COPY docker-entrypoint.sh /usr/local/bin/whatserv-entrypoint
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x /usr/local/bin/whatserv-entrypoint \
    && mkdir -p /data/sessions
ENV NODE_ENV=production
ENTRYPOINT ["whatserv-entrypoint"]
CMD ["node", "src/index.js"]
