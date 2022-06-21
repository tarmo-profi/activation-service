# activation-service
Service allowing to activate services and create policies in an iSHARE authorisation registry during the acquisition step.

## Configuration

Configuration is done in the file `config/as.yml`. You need to modify the values according to your 
environment and add your private key and certificate chain.

Private key and certificate chain can be also provided as ENVs as given below. In this case, the values from 
`config/as.yml` would be overwritten.
* Private key: `AS_CLIENT_KEY`
* Certificate chain: `AS_CLIENT_CRT`


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
docker run --rm -it -p 7000:7000 -v <PATH_TO_FILE>/as.yml:/home/aservice/config/as.yml activation-service:my-tag
```

### Kubernetes

A Helm chart is provided on [GitHub](https://github.com/i4Trust/helm-charts/tree/main/charts/activation-service) 
and [Artifacthub](https://artifacthub.io/packages/helm/i4trust/activation-service).



## Endpoints

* `/health`: Get health output of web server
* `/token`: Forwards a token request to the `/token` endpoint at the locally configured authorisation registry
* `/createpolicy`: Activates the service by creating a policy at the locally configured authorisation registry


## Extend

This version just allows to create policies at the local authorisation registry when the `/createpolicy` endpoint 
is called. 

However, depending on the service provided, it might be needed that further steps are required when activating 
a service, e.g. booting worker nodes or adding other resources. Such steps could be added as additional 
modules in the `./activation/` folder and be integrated in the `/createpolicy` endpoint implementation 
in `server.js`.


## Debug

Enable debugging by setting the environment variable:
```shell
DEBUG="as:*"
```
