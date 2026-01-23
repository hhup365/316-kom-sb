FROM node:alpine3.20

WORKDIR /app

RUN apk add --no-cache \
    gcompat \
    ca-certificates \
    tzdata \
    openssl

COPY . .

RUN chmod +x index.js

EXPOSE 3000/tcp

CMD ["node", "index.js"]
