# activation-service
Service allowing to activate services and create policies in an iSHARE authorisation registry during the acquisition step.

## Configuration

Configuration is done in the file `config/as.yml`. You need to modify the values according to your 
environment and add your private key and certificate chain.

## Usage

### Local

Run locally using `node.js`:
```shell
npm install
npm start
```


### Docker

A Dockerfile is provided for building the image:
```shell
docker build -t activation-service:my-tag .
```

Make a copy of the configuration file `config/as.yml` and modify according to your environment. 
Then run the image:
```shell
docker run --rm -it -p 7000:7000 -v <PATH_TO_FILE>/as.yml:/home/portal/config/as.yml activation-service:my-tag
```

### Kubernetes

tbd

