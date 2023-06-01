# vscpl1drv-logger

<img src="https://vscp.org/images/logo.png" width="100">

- **Available for**: Linux, Windows
- **Driver Linux**: vscpl2drv-logger.so
- **Driver Windows**: vscpl2drv-logger.dll

VSCP level II driver for diagnostic logging. It makes it possible to log VSCP events from a source to a file. Three formats of the log file is currently supported. Either a standard text string i logged for for each event or logging entries can be logged on XML or JSON format. The advantage of the later is that it can be read by VSCP works and further analyzed there. Several drivers can be used to write logging data to different output files and using different filter/masks for complex logging.

## Configuring the driver

### VSCP daemon configuration

The driver is enables int the VSCP daemon configuration file as all other drivers. The configuration looks like this

```json
"level2" : [
    {
        "enable" : true,
        "name" : "Logger",
        "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-logger.so",
        "path-config" : "/var/lib/vscp/v2logger.json",
        "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:02:00:00:00:00:00:00:01",

        "mqtt": {
          "bind": "",
          "host": "test.mosquitto.org",
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
              "topic": "vscp/tcpipsrv/{{guid}}/#",
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
    }
]
```

- **enable** should be set to *true* to make the VSCP daemon load the driver. Set to *false* to disable.
- **name** should be a system unique name you give your driver. 
- **path-driver** Is the path to where the driver is installed. Standard location is */var/lib/vscp/drivers/level2/vscpl2drv-logger.so*
- **path-config** Is the path to the driver configuration file. A good place to put this file is in */var/lib/vscp* or for higher security */etc/vscp*. Se below for more information.
- **guid** Is the GUID for the driver. All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html).

The *mqtt* section is configured as for mqtt configuration for the VSCP daemon. See [VSCP daemon documentation](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=config-mqtt) on the topic.

### Driver configuration

The driver configuration looks like this.

```json
{
  "debug" : true,
  "write" : false,
  "path" : "/var/log/vscp/vscplogger.log",
  "overwrite" : false,
  "logfmt" : 2, 
  "logging" : {
    "file-enable-log": true,
    "file-log-level" : "debug",
    "file-pattern" : "[vcpl2drv-logger %c] [%^%l%$] %v",
    "file-path" : "/var/log/vscp/vscpl2drv-logger.log",
    "file-max-size" : 5242880,
    "file-max-files" : 7,
    "console-enable-log": true,
    "console-log-level" : "debug",
    "console-pattern" : "[vcpl2drv-logger %c] [%^%l%$] %v"
  },
  "filter" : {
    "in-filter" : "incoming filter on string form",
    "in-mask" : "incoming mask on string form",
    "out-filter" : "outgoing filter on string form",
    "out-mask" : "outgoing mask on string form"
  } 
}
```

 - **debug** will write out extra debug information to syslog. Enable by setting to *true* if you experience problems.
 - **write** enables configuration write functionality if set to *true*. If enables remember that the configuration file must be placed at a location that is writable by the VSCP daemon.
 - **path** is the path to the file where the logging data will be written.
 - **overwrite** set to *true* to overwrite the data in the log file onm every restart. If set to false data will be appended to the log file.
 - **format** Can be set to zero for string log format, 1 for XML log format and 2 for JSON log format. 
 - **filter** can be used to filter the steam of events to just log a limited amount of events. Both are on format **priority, class, type, guid**. Default is to log all events. out-filter/out-mask is traffic from the interface. in-filter/in.mask is not used at the moment.

## Install the driver

Download the latest release from [https://github.com/grodansparadis/vscpl2drv-logger/releases](https://github.com/grodansparadis/vscpl2drv-logger/releases). Do

```bash
sudo apt install ../vscpl2drv-logger_x.x.x.deb
```
where x.x.x is the version of the driver.

The driver will be installed into */var/lib/vscp/drivers/level2*. A sample configuration file will be written to */var/lib/vscp*.

## Build the driver

Clone the repository with 

```bash
git clone https://github.com/grodansparadis/vscpl2drv-logger.git
```

or download one of the release archives from [https://github.com/grodansparadis/vscpl2drv-logger/releases](https://github.com/grodansparadis/vscpl2drv-logger/releases) and unpack.


To build the driver you follow the same procedure as with all autoconf based builds. Enter the source folder and do

```bash
cd vscpl2drv-logger
mkdir build
cd build
cmake ..
make
make install
sudo cpack .. (comment: only if you want to create install packages)

```

The driver will be installed into */var/lib/vscp/drivers/level2*. A sample configuration file will be written to */var/lib/vscp*.

## HLO configuration

![](./images/hlo.png)

This driver can be configured using High Level Object configuration. This is a web-based configuration interface that all VSCP level II drivers support.

The files needed for HLO configuration this not automatically installed at the moment but if you want to test HLO configuration just copy the files in the [forms folder](https://github.com/grodansparadis/vscpl2drv-logger) to you own disk and open the index.html file to get started.

## VSCP

There are many Level I and level II drivers available in VSCP & Friends framework that can be used with both VSCP Works and the VSCP Daemon and added to that Level II  that can be used with the VSCP Daemon.

You find a list of driver [here](https://docs.vscp.org/).

The VSCP project homepage is here <https://www.vscp.org>.

The [manual](https://docs.vscp.org/#vscpd) for vscpd contains full documentation. Other documentation can be found [here](https://docs.vscp.org/).

The vscpd source code may be downloaded from [https://github.com/grodansparadis/vscp](https://github.com/grodansparadis/vscp). Source code for other system components of VSCP & Friends are here [https://github.com/grodansparadis](https://github.com/grodansparadis)

## COPYRIGHT
Copyright (C) 2000-2023 Ake Hedman, Grodans Paradis AB - MIT license.
