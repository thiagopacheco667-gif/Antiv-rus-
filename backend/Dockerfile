FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY scripts ./scripts
USER node
EXPOSE 8443
CMD ["node", "src/index.mjs"]
