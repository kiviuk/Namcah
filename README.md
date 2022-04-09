# Hacman

Hacman is a Http client for the HAC Scripting Console of SAP Commerce.
Hacman uploads local groovy files to HAC and lets them run on the server.

## Features

- unsupervised login into the HAC
- terminates long-running http requests

## Building from source

Java 11 is required

```sh
cd Hacman
mvn install package

Installs hacman.jar to ./target 
```

## Running

```sh
hacman --help
Usage: java -jar hacman.jar [options] <Groovy-Script Location>
  Options:
    --username, -u
      <Hac username>, default 'admin'
    --password, -p
      <HAC password>, default 'nimda'
    --commerce, -c
      <SAP commerce URL>, default https://127.0.0.1:9002
    --help
      This help message
```
Example:
```
java -jar ./target/hacman.jar ./target/classes/updateLogLevel.txt  
```
runs script through https://127.0.0.1:9002/hac by using the default host, username and password.

Example groovy scripts:
```
clusterLoggingService.changeLogLevel("de.hybris.platform.servicelayer","DEBUG")
clusterLoggingService.changeLogLevel("net.netconomy.dglcore.media","DEBUG")
```
or
```
spring.beanDefinitionNames.each {
    println it
}
return "Groovy Rocks!"
```
## License

MIT

**Free Software 👍**
