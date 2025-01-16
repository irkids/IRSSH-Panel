# docker/frontend/Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy source code
COPY frontend/ .

# Build application
RUN npm run build

# Install serve
RUN npm install -g serve

CMD ["serve", "-s", "build", "-l", "3000"]
