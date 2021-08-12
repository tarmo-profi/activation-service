FROM node:10

# User
RUN groupadd --gid 5000 aservice \
    && useradd --home-dir /home/aservice --create-home --uid 5000 \
        --gid 5000 --shell /bin/sh --skel /dev/null aservice
COPY . /home/aservice
USER aservice
WORKDIR /home/aservice

# npm
RUN npm install

# Start
EXPOSE 7001
CMD [ "npm", "start" ]
