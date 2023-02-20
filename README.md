# Namcah

Namcah is a straightforward http client that operates on the command line and is designed to interact with the HAC Scripting Console in SAP Commerce. With Namcah, you can transmit a groovy script file to a remote HAC scripting console and execute it on the spot.

By logging the root SSL key, the HTTPS communication between the IntelliJ Hybris integration plugin and the Hybris service was decrypted using WireShark.

Using https://hc.apache.org/httpcomponents-client-5.1.x
## Features

- auto-login
- control HAC commit mode
- terminates long-running http requests
- auto-detect background nodes
- supports *nix pipe

## Building from source

Tested on Java 11/17/18

```sh
# Clone the project
git clone git@github.com:kiviuk/Namcah.git

# Build & install namcah.jar to ./target 
cd Namcah
mvn install package
```

## Running

```sh
java -jar namcah.jar --help

Usage: java -jar namcah.jar [options]
  Options:
    --username, -u
      <Hac username>, default 'admin'
    --password, -p
      <HAC password>, default 'nimda'
    --commerce, -c
      <SAP commerce URL>, default https://127.0.0.1:9002
    --commit, -t
      Controls the HAC commit mode
      Default: false
    --route, -r
      The node route in case of a background processing node
    --script, -s
      Location of the groovy script
    --debug, -d
      Enable debug level, (logs are kept in namcah.log)
      Default: false
    --help, -h
      This help

Example 1:
 echo '"ls -hl /".execute().text' | java -jar ./target/namcah.jar -c https://localhost:9002 -u admin -p nimda
Example 2:
 java -jar ./target/namcah.jar -s /home/user/scripts/script.txt -c https://localhost:9002 -u admin -p nimda
Use 'echo $?' to grep the system exit code: 0 = OK, 1 = Error
```

Examples: 
```
# Run cronjobs on https://127.0.0.1:9002/hac
# using the default host, username and password.
java -jar ./target/namcah.jar ./target/classes/scripts/runCronJob-dl.txt

# Run the obligatory Groovy Rocks! on https://127.0.0.1:9002/hac
java -jar ./target/namcah.jar ./target/classes/scripts/groovyRocks.txt -c https://localhost:9002 -u someUser -p somePassword

# Output
Executing script: return "Groovy Rocks!"
Commerce: https://127.0.0.1:9002
Route: main
Script: ./target/classes/scripts/groovyRocks.txt
<namcah>
Groovy Rocks!
</namcah>

```
Example scripts:
```
# Find more example scripts in ./target/classes/scripts

# Run cron job
def cronJob = cronJobDao.findCronJobs("aCronJob")
cronJobService.performCronJob(cronJob)

# Update log levels
clusterLoggingService.changeLogLevel("de.hybris.platform.servicelayer","DEBUG")

# Groovy Rocks
return "Groovy Rocks!"


```
## License

MIT
