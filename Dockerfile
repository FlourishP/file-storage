FROM node:20-slim

WORKDIR /app

COPY package.json .
RUN npm install

COPY main.ts .
COPY tsconfig.json .

EXPOSE 8006
CMD ["npm", "start"]