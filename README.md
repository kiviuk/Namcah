# Hacman

Hacman is a simple http client for the HAC Scripting Console of SAP Commerce.
Use Hacman to send a groovy file to HAC and execute it there.

## Features

- auto-login into the HAC
- control commit mode
- terminates long-running http requests

## Building from source

Java 11 is required

```sh
git clone git@github.com:kiviuk/Hacman.git

cd Hacman
mvn install package

Installs hacman.jar to ./target 
```

## Running

```sh
hacman --help

Usage: java -jar hacman.jar [options] <Groovy-Script Location>
- Example: 
 
      java -jar ./target/hacman.jar ./target/classes/groovyRocks.txt -c 
      https://localhost:9002 -u admin -p nimda. Use 'echo $?' to grep the 
      system exit code: 0 = Ok, 1 = Error

  Options:
    --username, -u
      <Hac username>, default 'admin'
    --password, -p
      <HAC password>, default 'nimda'
    --commerce, -c
      <SAP commerce URL>, default https://127.0.0.1:9002
    --commit, -t
      Enable HAC commit mode
      Default: false
    --debug, -d
      Enable debug level
      Default: false
    --help, -h
      This help


```
Examples:
```
# Using the default host, user & pasword to update log levels
java -jar ./target/hacman.jar ./target/classes/updateLogLevel.txt

# Output
<script-result>
void
</script-result>

java -jar ./target/hacman.jar ./target/classes/groovyRocks.txt -c https://localhost:9002 -u someUser -p somePassword

# Output
<script-result>
Groovy Rocks!
</script-result>

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
