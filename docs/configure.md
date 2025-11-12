
A VSCP level II  driver can be used with all VSCP level II host applications like the VSCP daemon and VSCP Works. The interface is very simple and is easily implemented also by other programs.

# vscpl2drv-logger driver config

On start up the configuration is read from the path set in the driver configuration of the VSCP daemon, usually */etc/vscp/conf-file-name* and values are set from this location. 

Normally you find the driver configuration file in one of these locations

| Platform | Standard configuration file path |
| -------- | ----------------------- |
| Linux    | /etc/vscpl2drv-logger.json    |
| Windows  | C:\users\<user>\local\vscp\vscpl2drv-logger.json |
| MacOS   | /etc/vscp/vscpl2drv-logger.json    |

but you can put it wherever you want as long as the application using the driver has read access to it.

If the **write** parameter is set to "true" the  application that use the driver **must** be able to write to it. If this feature is used the standard locations are not the best places to put the file as they often require elevated privileges to write to if placed there.

The configuration file have the following format

```json
{
  "debug" : true,
  "write" : false,
  "path" : "/tmp/vscplogger.log",
  "overwrite" : false,
  "logfmt" : 2, 
  "filter" : "0,0x0000,0x0000,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
  "mask" : "0,0x0000,0x0000,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
  "logging" : {
    "log-level" : "debug",
    "file-enable-log": true,
    "file-pattern" : "[vcpl2drv-logger %c] [%^%l%$] %v",
    "file-path" : "/tmp/vscpl2drv-logger.log",
    "file-max-size" : 5242880,
    "file-max-files" : 7,
    "console-enable-log": true,
    "console-pattern" : "[vcpl2drv-logger %c] [%^%l%$] %v"
  }
}
```

A default configuration file is written to [/usr/share/vscp/drivers/level2/vscpl2drv-logger](/usr/share/vscp/drivers/level2/vscpl2drv-logger) when the driver is installed. The repository contains a sample configuration file that can be used as a starting point [here](https://github.com/grodansparadis/vscpl2drv-logger/blob/main/debug/conf_standard.json).

## debug
Set debug to _true_ to get extra debug information written to the log file. This can be a valuable help if things does not behave as expected. This is only for extra debug information. Normal error and info messages are always logged according to the logging settings.

## write (currently not used)
If write is true dynamic changes to the configuration file will be possible to save dynamically to disk. That is, settings you do at runtime can be saved and be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but for dynamic saves are not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivers/level2/configure.json*. 

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder is a good choice.

## path
Path to the log file. Default is */tmp/vscpl2drv-logger.log*
## overwrite
Set to true to overwrite existing log file on start up. Default is false meaning that new log entries are appended to existing log file.
## logfmt
Log format. Possible values are:  
  0 : Plain text log format  
  1 : CSV log format  
  2 : JSON log format






## filter
Set a default filter/mask for incoming events. The format is `priority,vscpclass,vscptype,GUID;priority-mask,vscpclass-mask,vscptype-mask,GUID-mask` where each field in the filter part (before the ';') can be a specific value. Values in the mask tells which bits in the filter that should be checked. A bit set to zero means "ignore". All bits set to one means "the value must be the same as in the first part". As an example the filter/mask

> 0,10,6,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01;0,255,255,00:00:00:00:00:00:00:00:00:00:00:00:00:FF

means that all events with class 10 and type 6 and any GUID with last byte set to 1 will pass the filter.

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given in hexadecimal (without preceded '0x').

## mask
Set a default filter/mask for incoming events. The format is `priority,vscpclass,vscptype,GUID;priority-mask,vscpclass-mask,vscptype-mask,GUID-mask` where each field in the filter part (before the ';') can be a specific value. Values in the mask tells which bits in the filter that should be checked. A bit set to zero means "ignore". All bits set to one means "the value must be the same as in the first part". As an example the filter/mask

> 0,10,6,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01;0,255,255,00:00:00:00:00:00:00:00:00:00:00:00:00:FF means that all events with class 10 and type 6 and any GUID with last byte set to 1 will pass the filter.

## Logging
In this section is the log console and log file settings. Before the configuration file is read logging will be sent to the console. 

Modes for logging can be set as of below. In debug/trace mode the debug flag above defines how much info is logged.

### log-level :id=config-general-logging-log-level
Log level for log. Default is "info".

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

### Logging to console

#### console-enable-log :id=config-general-logging-console-enable-log
Enable logging to a console by setting to *true*.



#### console-pattern :id=config-general-logging-console-pattern

Format for consol log.

### Logging to file

#### file-enable
Enable logging to a file by setting to _true_.

#### file-log-level 
Log level for file log. Default is _"info"_.

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

#### file-pattern :id=config-general-logging-file-pattern
Log file pattern as described [here](https://github.com/gabime/spdlog/wiki/3.-Custom-formatting).

#### file-path :id=config-general-logging-file-path
Set a writable path to a file that will get log information written to that file. This can be a valuable help if things does not behave as expected.

#### file-max-size :id=config-general-logging-file-max-size
Max size for log file. It will be rotated if over this size. Default is 5 Mb.

#### file-max-files :id=config-general-logging-file-max-files
Maximum number of log files to keep. Default is 7.

## filter
Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

**Default**: setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

## mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

## Windows
See information from Linux. The only difference is the disk location from where configuration data is fetched.

## VSCP daemon driver config

To use the libvscpl2drv-logger.so driver with the VSCP daemon there must be an entry in the level2 driver section of its configuration file. The location for the file is different for different platforms as in this table

| Platform | Standard configuration file path |
| -------- | ----------------------- |
| Linux    | /etc/vscp/vscpd.json    |
| Windows  | C:\users\<user>\local\vscp\vscpd.json |
| MacOS   | /etc/vscp/vscpd.json    |

The entry in the level2 driver section should look like this

```json
"drivers": {
    "level2": [
```

The format is

```json
{
  "enable" : true,
  "name" : "l2logger",
  "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-logger.so",
  "path-config" : "/etc/vscp/logger.json",
  "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:02:88:88:00:00:00:00:01",

  "mqtt": {
    "bind": "",
    "host": "test.mqtt.org",
    "port": 1883,
    "mqtt-options": {
      "tcp-nodelay": true,
      "protocol-version": 311,
      "receive-maximum": 20,
      "send-maximum": 20,
      "ssl-ctx-with-defaults": 0,
      "tls-ocsp-required": 0,
      "tls-use-os-certs": 0
    },
    "user": "vscp",
    "password": "secret",
    "clientid": "the-vscp-daemon logger driver",
    "publish-format": "json",
    "subscribe-format": "auto",
    "qos": 1,
    "bcleansession": false,
    "bretain": false,
    "keepalive": 60,
    "bjsonmeasurementblock": true,
    "reconnect": {
      "delay": 2,
      "delay-max": 10,
      "exponential-backoff": false
    },
    "tls": {
      "cafile": "",
      "capath": "",
      "certfile": "",
      "keyfile": "",
      "pwkeyfile": "",
      "no-hostname-checking": true,
      "cert-reqs": 0,
      "version": "",
      "ciphers": "",
      "psk": "",
      "psk-identity": ""
    },
    "will": {
      "topic": "vscp-daemon/{{srvguid}}/will",
      "qos": 1,
      "retain": true,
      "payload": "VSCP Daemon is down"
    },
    "subscribe" : [
      {
        "topic": "vscp/logger/{{guid}}/#",
        "qos": 0,
        "v5-options": 0,
        "format": "auto"
      }
    ],
    "publish" : [
      {
        "topic": "vscp/{{guid}}/{{class}}/{{type}}/{{nodeid}}",
        "qos": 1,
        "retain": false,
        "format": "json"
      }
    ]
  }
}
```
### enable
Set enable to "true" if the driver should be loaded by the VSCP daemon.

### name
This is the name of the driver. Used when referring to it in different interfaces.

### path-driver
This is the path to the driver. If you install from a Debian package this will be */var/lib/vscp/drivers/level2/libvscpl2drv-logger.so*.

### path-config
This is the path to the driver configuration file (see below). This file determines the functionality of the driver. A good place for this file is in _/etc/vscp/logger.json_ It should be readable only by the user the VSCP daemon is run under (normally _vscp_) as it holds credentials to log in to a remote VSCP websocket interface. Never make it writable at this location.

### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html). The tool [vscp_eth_to_guid](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=think-before-guid) is a useful tool that is shipped with the VSCP daemon that will get you a unique GUID if you are working on a machine with an Ethernet interface.

### mqtt
See the [VSCP configuration documentation](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=config-mqtt) for info about this section. It is common for all drivers loaded by the VSCP daemon.

## VSCP Works driver config

In VSCP Works you add the driver in the connection dialog in the level II driver section. You need to set the path to the driver and the path to the configuration file as above.

Using the level II driver interface as a connection in this way make it possible to open both server and client connections to VSCP websocket interfaces (and others) for debugging and development.







[filename](./bottom-copyright.md ':include')