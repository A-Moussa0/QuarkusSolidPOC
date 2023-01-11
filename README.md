# code-with-quarkus Project

This project uses Quarkus, the Supersonic Subatomic Java Framework.

If you want to learn more about Quarkus, please visit its website: https://quarkus.io/ .

## Prerequisites / dependencies
- Docker/docker-compose (usually packaged together if using docker desktop)
  > https://docs.docker.com/
- Java 11+
  > https://docs.oracle.com/en/java/javase/index.html
- Node.js & npm
  > https://docs.npmjs.com/downloading-and-installing-node-js-and-npm

## Before Running the application
Move `application.properties-sample` to `src/main/resources` and rename it to `application.properties` and edit it to suite your needs.\

You need to start docker and cd into the project root and execute the following command in order to spin up both the database and the keycloak authentication server:
> This will run the services in the docker-compose.yaml file, you can edit whatever configurations in there to suite your specific needs.
**_-f_** to specify file name **_-d_** to run in detach mode.\
*It is recommended to __not run__ in detach mode in the beginning so you can see the logs live and make sure everything is up.*
```shell script
docker compose -f docker-compose.yaml up -d
```
> Note that the keycloak server will import another realm(quarkus) which is configured to work with this project, you change that by directly editing the file in keycloak-import directory.\
> Alternatevly, you can make all your changes after the keycloak server is up and extract the configuration json file using the below command:
```shell script
docker exec quarkussolidpoc-keycloak-1 ./opt/keycloak/bin/kc.sh --verbose export --file /opt/keycloak/export/realm-export.json --realm quarkus
```

---

To entirely remove the containers you can run the below command:
```shell script
docker compose -f docker-compose.yaml down
```


## Running the application in dev mode

You can run your application in dev mode that enables live coding using:
```shell script
./mvnw compile quarkus:dev
```

> **_NOTE:_**  Quarkus now ships with a Dev UI, which is available in dev mode only at http://localhost:8181/q/dev/.

## Packaging and running the application

The application can be packaged using:
```shell script
./mvnw package
```
It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

The application is now runnable using `java -jar target/quarkus-app/quarkus-run.jar`.

If you want to build an _über-jar_, execute the following command:
```shell script
./mvnw package -Dquarkus.package.type=uber-jar
```

The application, packaged as an _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

For the application to run in the background and not be killed when you exit the terminal, you can run the command like so:
```shell script
nohup java -jar ./quarkus-solid-poc-1.0.0-SNAPSHOT-runner.jar &
```

## Creating a native executable

You can create a native executable using:
```shell script
./mvnw package -Pnative
```

Or, if you don't have GraalVM installed, you can run the native executable build in a container using:
```shell script
./mvnw package -Pnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/code-with-quarkus-1.0.0-SNAPSHOT-runner`

If you want to learn more about building native executables, please consult https://quarkus.io/guides/maven-tooling.

### RESTEasy Reactive

Easily start your Reactive RESTful Web Services

[Related guide section...](https://quarkus.io/guides/getting-started-reactive#reactive-jax-rs-resources)
