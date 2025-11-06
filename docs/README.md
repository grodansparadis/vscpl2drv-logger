
## Documentation for the vscpl2drv-logger driver

**Document version:** ${/var/document-version} - ${/var/creation-time}
[HISTORY](./history.md)

![driver model](/images/xmap-vscpl2drv-logger.png)

VSCP level II driver for diagnostic logging. It makes it possible to log VSCP events from a source to a file. Three formats of the log file is currently supported. Either a standard text string i logged for for each event or logging entries can be logged on XML or JSON format. The advantage of the later is that it can be read by VSCP works and further analyzed there. Several drivers can be used to write logging data to different output files and using different filter/masks for complex logging.


The level II driver is [described here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_driver_interfaces). With the simple interface API the VSCP level II driver uses (described above) it is also easy to use it with other software as a component.

* [Repository for the module](https://github.com/grodansparadis/${/var/driver-name})
* This manual is available [here](https://grodansparadis.github.io/${/var/driver-name})


## VSCP - the Very Simple Control Protocol (framework)

![VSCP logo](./images/logo_100.png)

VSCP is a free and open automation protocol for IoT and m2m devices. Visit [the VSCP site](https://www.vscp.org) for more information.

**VSCP is free.** Placed in the **public domain**. Free to use. Free to change. Free to do whatever you want to do with it. VSCP is not owned by anyone. VSCP will stay free and gratis forever.

The specification for the VSCP protocol is [here](https://grodansparadis.github.io/vscp-doc-spec/#/) 

VSCP documentation for various parts of the protocol/framework can be found [here](https://docs.vscp.org/).

If you use VSCP please consider contributing resources or time to the project ([https://github.com/sponsors/grodansparadis](https://github.com/sponsors/grodansparadis)).


## Document license

This document is licensed under [Creative Commons BY 4.0](https://creativecommons.org/licenses/by/4.0/) and can be freely copied, redistributed, remixed, transformed, built upon as long as you give credits to the author.


[filename](./bottom-copyright.md ':include')
