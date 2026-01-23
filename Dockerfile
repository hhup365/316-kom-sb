FROM node:alpine3.20

WORKDIR /app

RUN apk add --no-cache \
    gcompat \
    ca-certificates \
    bash \
    curl \
    openssl \
    iproute2 \
    coreutils \
    tzdata

COPY . .

RUN npm install axios && \
    chmod +x index.js

EXPOSE 3000/tcp

CMD ["node", "index.js"]
