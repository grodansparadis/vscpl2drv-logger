
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
// the vscpl2drv-logger driver. Use {{guid}} for this or set
// it explicitly.
mqtt.publish = "vscp/{{guid}}";
mqtt.subscribe = "vscp/{{guid}}/#";

mqtt.timeout = 30;
mqtt.keepalive = 60;
mqtt.cleansession = true;
mqtt.reconnect = false;
mqtt.willmessage = "disconnected";
