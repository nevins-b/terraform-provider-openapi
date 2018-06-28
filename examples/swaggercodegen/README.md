# Swagger codegen service provider example

This example was created using [swagger-codegen](https://github.com/swagger-api/swagger-codegen) tool. Using the generator
 we have created a service provider that exposes a resource for managing 'CDNs' allowing the consumer to create and read CDNs.

## Overview
This server was generated by the [swagger-codegen](https://github.com/swagger-api/swagger-codegen) project.  
By using the [OpenAPI-Spec](https://github.com/OAI/OpenAPI-Specification) from a remote server, you can easily generate a server stub.

To see how to make this your own, look here:

[README](https://github.com/swagger-api/swagger-codegen/blob/master/README.md)

- API version: 0.0.1
- Build date: 2017-10-28T10:56:37.853-07:00


### Running the server
To run the server, follow these simple steps:

```
$ cd $GOPATH/github.com/dikhan/terraform-provider-openapi/examples/swaggercodegen/api
$ go run main.go
```


### Create swagger-ui

```
$ cd $GOPATH/github.com/dikhan/terraform-provider-openapi/examples/swaggercodegen/api
$ docker run -p 8082:8080 -e SWAGGER_JSON=/app/resources/swagger.yaml -v $(pwd):/app  swaggerapi/swagger-ui
```

### Curl commands

- Create new CDN

```
$ curl -X POST http://localhost/v1/cdns -d '{"label":"label", "ips":["127.0.0.1"], "hostnames":["www.origin.com"]}'
```

- Get info about previously created CDN

```
$ curl http://localhost/v1/cdns/<CDN_ID>'
```

- Update CDN

```
$ curl -X PUT http://localhost/v1/cdns/<CDN_ID> -d '{"label":"label updated", "ips":["127.0.0.1"], "hostnames":["www.origin.com"]}'
```

- Delete exiting CDN

```
$ curl -X DELETE http://localhost/v1/cdns/<CDN_ID>'
```