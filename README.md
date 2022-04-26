# Namcah

Namcah is a simple Java http client for the HAC Scripting Console of SAP Commerce.

Use Namcah from the command line to send a groovy script file to a remote HAC scripting console 
and to execute it right there.

Based on https://hc.apache.org/httpcomponents-client-5.1.x
## Features

- auto-login
- control HAC commit mode
- terminates long-running http requests
- for the command line

## Building from source

Tested on Java 11

```sh
# Clone the project
git clone git@github.com:kiviuk/Namcah.git

# Build & install namcah.jar to ./target 
cd Namcah
mvn install package
```

## Running

```sh
namcah --help

Usage: java -jar namcah.jar [options] <Groovy-Script Location>
- Example:

      java -jar ./target/namcah.jar ./target/classes/groovyRocks.txt -c
      https://localhost:9002 -u admin -p nimda. Use 'echo $?' to grep the
      system exit code: 0 = OK, 1 = Error

  Options:
    --username, -u
      <Hac username>, default 'admin'
    --password, -p
      <HAC password>, default 'nimda'
    --commerce, -c
      <SAP commerce URL>, default https://127.0.0.1:9002
    --commit, -t
      Control hAC commit mode
      Default: false
    --route, -r
      The node route in case of a background processing node
    --debug, -d
      Enable debug level, (logs are kept in namcah.log)
      Default: false
    --help, -h
      This help
      
      
```

Examples: 
```
# Run cronjobs on https://127.0.0.1:9002/hac
# using the default host, username and password.
java -jar ./target/namcah.jar ./target/classes/runCronJob-dl.txt

# Output
<namcah>
void
</namcah>

# Update log levels for https://127.0.0.1:9002/hac
java -jar ./target/namcah.jar ./target/classes/updateLogLevel.txt

# Output
<namcah>
void
</namcah>

# Run the obligatory Groovy Rocks! on https://127.0.0.1:9002/hac
java -jar ./target/namcah.jar ./target/classes/groovyRocks.txt -c https://localhost:9002 -u someUser -p somePassword

# Output
<namcah>
Groovy Rocks!
</namcah>

```
Example scripts:
```
# Find example scripts in ./target/classes

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
