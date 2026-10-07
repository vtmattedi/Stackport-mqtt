## NightMare profile

This deployment serves the NightMare fleet. Gateways and devices use the `nmnw` role, which lets a client publish and subscribe to every application topic but never reach `$CONTROL`. Create gateway clients with `provision-client.sh <user> nmnw`, or in this console with the `nmnw` role.

Firmware that stores its credentials in `creds.h` needs the host, the port, the CA certificate and the client's username and password:

```c
#define MQTT_HOST "{{host}}"
#define MQTT_PORT {{port}}
#define MQTT_USER "<username>"
#define MQTT_PASS "<password>"
```
