# Build image from node.
ARG NODE_VERSION=20.14.0

FROM node:${NODE_VERSION}-alpine

#Set Node.js environment (Useful for error messages, caching, etc)
ENV NODE_ENV development

WORKDIR /app

#Copy package files to help install dependencies
COPY package.json package.json
COPY package-lock.json package-lock.json

#Install dependencies
RUN npm install
RUN npm install express axios



#Copy rest of source files
COPY . .

CMD ["npm","run","devStart"]
# CMD ["node","app.js"]
