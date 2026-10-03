FROM node:20.11.1
RUN apt update
RUN apt install -y \
  openssl \
  libssl-dev \
  make \
  g++ \
  cmake
RUN mkdir -p /opt/app/fuzzz-relay
RUN mkdir -p /opt/app/fuzzz-relay/public

COPY package.json package-lock.json ./opt/app/fuzzz-relay/
COPY ./ ./opt/app/fuzzz-relay
WORKDIR /opt/app/fuzzz-relay

RUN npm install --force
EXPOSE 8765

CMD [ "npm", "start"]