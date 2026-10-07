## Perfil NightMare

Esta implantação atende a frota NightMare. Gateways e dispositivos usam a função `nmnw`, que permite publicar e assinar em todos os tópicos de aplicação, mas nunca acessar `$CONTROL`. Crie clientes de gateway com `provision-client.sh <usuario> nmnw`, ou neste console com a função `nmnw`.

Firmware que guarda as credenciais em `creds.h` precisa do host, da porta, do certificado da CA e do usuário e senha do cliente:

```c
#define MQTT_HOST "{{host}}"
#define MQTT_PORT {{port}}
#define MQTT_USER "<usuario>"
#define MQTT_PASS "<senha>"
```
