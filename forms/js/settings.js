
/*!
    Settings for VSCP MQTT communication
*/
var mqtt = {};
mqtt.host = "192.168.1.7";
mqtt.port = 9001;
mqtt.clientid = "vscp-logger-client1234";
mqtt.username = "vscp";
mqtt.password = "secret";
// GUID is normally the same as set in VSCP daemon config file for 
// the vscpl2drv-logger driver. 
mqtt.publish = "vscp/FF:FF:FF:FF:FF:FF:FF:F5:05:00:00:00:00:00:00:00";
mqtt.subscribe = "vscp/FF:FF:FF:FF:FF:FF:FF:F5:05:00:00:00:00:00:00:00/#";

mqtt.timeout = 30;
mqtt.keepalive = 60;
mqtt.cleansession = true;

// This is the GUID used as originating GUID for sent events
// https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_globally_unique_identifiers
mqtt.ourguid = "FF:FF:FF:FF:FF:FF:FF:F5:FF:FF:FF:FF:FF:FF:FF:FF";

