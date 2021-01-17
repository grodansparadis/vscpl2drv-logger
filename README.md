# vscpl1drv-logger

<img src="https://vscp.org/images/logo.png" width="100">

- **Available for**: Linux, Windows
- **Driver Linux**: vscpl2drv-logger.so
- **Driver Windows**: vscpl2drv-logger.dll

VSCP level II driver for diagnostic logging. It makes it possible to log VSCP events from a source to a file. Three formats of the log file is supported. Either a standard text string i loged for for each event or logging entries can be logged on XML or JSON format. The advantage of the later is that it can be read by VSCP works and further analyzed there. Several drivers can be used to write logging data to different output files and using different filter/masks for complex logging.

## Configuring the driver

### VSCP daemon configuration

The driver is enables int the VSCP daemon configuration file as all other drivers. The configuration looks like this

```json
"level2" : [
    {
        "enable" : true,
        "name" : "Logger",
        "path-driver" : "/var/lib/vscp/drivers/level2/vscpl2drv-logger.so",
        "path-config" : "/var/lib/vscp/vscpl2drv-logger.json",
        "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:02:00:00:00:00:00:00:01",

        "mqtt" : {
            "host" : "127.0.0.1",
            "port" : 1883,
            "user" : "vscp",
            "password": "secret",
            "clientid" : "mosq-vscp-logger-000001",
            "format" : "json",
            "qos" : 0,
            "bcleansession" : false,
            "bretain" : false,
            "keepalive" : 60,
            "reconnect-delay" : 10,
            "reconnect-delay-max" : 100,
            "reconnect-exponential-backoff" : false,
            "cafile" : "",
            "capath" : "",
            "certfile" : "",
            "keyfile" : "",
            "pwkeyfile" : "",
            "subscribe" : [
                "vscp/#"
            ],
            "publish" : [
                
            ]
        }
    }
]
```

- **enable** should be set to *true* to make the VSCP daemon load the driver. Set to *false* to disable.
- **name** should be a system unique name you give your driver. 
- **path-driver** Is the path to where the driver is installed. Standard location is */var/lib/vscp/drivers/level2/vscpl2drv-logger.so*
- **path-config** Is the path to the driver configuration file. A good place to put this file is in */var/lib/vscp* or for higher security */etc/vscp*. Se below for more information.

The *mqtt* section is optional and the main MQTT settings for the VSCP daemon will be used for all entries that is not present. The subscribe topic is however probably something that is set to a different value than for the general settings as this is the topic subscribed to to get logging entries.

### Driver configuration

The driver configuration looks like this.

```json
{
    "debug" : true,
    "write" : false,
    "path" : "/tmp/vscplogger.log",
    "overwrite" : false,
    "format" : 2, 
    "filter" : "0,0x0000,0x0000,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
    "mask" : "0,0x0000,0x0000,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" 
}
```

 - **debug** will write out extra debug information to syslog. Enable by setting to *true* if you experience problems.
 - **write** enables configuration write functionality if set to *true*. If enables remember that the configuration file must be placed at a location that is writable by the VSCP daemon.
 - **path** is the path to the file where the logging data will be written.
 - **overwrite** set to *true* to overwrite the data in the log file onm every restart. If set to false data will be appended to the log file.
 - **format** Can be set to zero for string log format, 1 for XML log format and 2 for JSON log format. 
 - **filter**/**mask** can be used to filter the steam of events. Both are **priority, class, type, guid**. Default is to log all events.

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
./configure
make
sudo make install
```

The driver will be installed into */var/lib/vscp/drivers/level2*. A sample configuration file will be written to */var/lib/vscp*.

## HLO configuration

This driver can be will later be able configured using High Level Object configuration. 

## VSCP

There are many Level I drivers available in VSCP & Friends framework that can be used with both VSCP Works and the VSCP Daemon and added to that Level II and Level III drivers that can be used with the VSCP Daemon.

You find a list of driver [here](https://docs.vscp.org/).

If you want to build your own driver, information on how to do so can be found here

Level I drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_i_drivers.html).

Level II drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_ii_drivers.html)


The VSCP project homepage is here <https://www.vscp.org>.

The [manual](https://docs.vscp.org/#vscpd) for vscpd contains full documentation. Other documentation can be found [here](https://docs.vscp.org/).

The vscpd source code may be downloaded from [https://github.com/grodansparadis/vscp](https://github.com/grodansparadis/vscp). Source code for other system components of VSCP & Friends are here [https://github.com/grodansparadis](https://github.com/grodansparadis)

## COPYRIGHT
Copyright (C) 2000-2021 Ake Hedman, Grodans Paradis AB - MIT license.
