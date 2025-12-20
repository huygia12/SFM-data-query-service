FROM node:21-alpine@sha256:78c45726ea205bbe2f23889470f03b46ac988d14b6d813d095e2e9909f586f93 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY src/prisma src/prisma
RUN npx prisma generate --schema ./src/prisma/schema.prisma
COPY . .
RUN npm run build

FROM node:21-alpine@sha256:78c45726ea205bbe2f23889470f03b46ac988d14b6d813d095e2e9909f586f93 AS final
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}
WORKDIR /app
COPY package*.json ./
RUN npm pkg delete scripts.prepare
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
COPY src/prisma prisma
RUN npx prisma generate --schema ./prisma/schema.prisma

EXPOSE 4000
ENTRYPOINT [ "node", "dist/index.js" ]