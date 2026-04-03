FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src/ ./src/
COPY scripts/ ./scripts/

RUN mkdir -p logs

EXPOSE 3000

CMD ["node", "src/app.js"]
