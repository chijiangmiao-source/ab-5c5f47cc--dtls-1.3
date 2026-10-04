FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /app

# Zero runtime dependencies: no npm install step required.
COPY package.json ./
COPY src ./src
COPY public ./public
COPY verify ./verify

ENV PORT=8080
ENV DATA_DIR=/app/data
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
