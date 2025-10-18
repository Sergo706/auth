# syntax=docker/dockerfile:1

FROM ubuntu:latest
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt update && apt install -y curl git age
ENV BASH_ENV=/.bash_env
RUN touch "${BASH_ENV}"
RUN echo '. "${BASH_ENV}"' >> ~/.bashrc
ENV NVM_DIR=/opt/nvm
RUN mkdir -p "$NVM_DIR"
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | PROFILE="${BASH_ENV}" bash
RUN echo node > .nvmrc
RUN nvm install
RUN ln -s "$(which node)" /usr/local/bin/node
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup --system --gid 10001 appuser && \
    adduser --system --uid 10001 --gid 10001 --home /home/appuser --shell /bin/false appuser
RUN mkdir -p /app/logs
COPY package*.json ./
COPY tsconfig.prod.json ./
COPY config.json.age .
COPY decrypt.sh .
COPY . .
RUN chmod +x decrypt.sh
RUN chown -R appuser:appuser /app /home/appuser
USER appuser
RUN --mount=type=ssh,uid=10001,gid=10001 npm install --foreground-scripts --ignore-scripts=false
RUN npm run build:prod
EXPOSE 10000 
HEALTHCHECK --interval=30s --timeout=5s --retries=5 --start-period=60s \
  CMD sh -c 'code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:10000/health || echo 000); [ "$code" = "200" ] || [ "$code" = "401" ]'
ENTRYPOINT ["./decrypt.sh"]  
CMD ["node", "dist/service.js"]