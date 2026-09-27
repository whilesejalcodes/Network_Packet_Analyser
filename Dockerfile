FROM node:24-bookworm

# Install the C++ compiler and build tools required by the DPI engine
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better Docker layer caching
COPY package.json package-lock.json ./
RUN npm ci

# Copy the project source
COPY . .

# Build the C++ DPI engine and the production web application
RUN npm run build

# Render provides PORT at runtime
ENV NODE_ENV=production

EXPOSE 10000

CMD ["npm", "start"]