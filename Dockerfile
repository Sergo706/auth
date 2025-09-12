# syntax=docker/dockerfile:1

FROM ubuntu:latest
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt update && apt install curl -y && apt install -y git
ENV BASH_ENV=/.bash_env
RUN touch "${BASH_ENV}"
RUN echo '. "${BASH_ENV}"' >> ~/.bashrc
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | PROFILE="${BASH_ENV}" bash
RUN echo node > .nvmrc
RUN nvm install
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
COPY tsconfig.prod.json ./
RUN --mount=type=ssh npm install --foreground-scripts --ignore-scripts=false
COPY . .
RUN npm run build:prod
EXPOSE 10000 
HEALTHCHECK --interval=5m --timeout=20s --start-period=40s \
  CMD curl -f http://localhost:10000/health || exit 1
CMD ["node", "dist/service.js"];