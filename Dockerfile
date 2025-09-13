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
RUN ln -s "$(which node)" /usr/local/bin/node
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
COPY tsconfig.prod.json ./
RUN --mount=type=ssh npm install --foreground-scripts --ignore-scripts=false
COPY . .
RUN npm run build:prod
EXPOSE 10000 
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD sh -c 'code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:10000/health || echo 000); [ "$code" = "200" ] || [ "$code" = "401" ]'
CMD ["node", "dist/service.js"]