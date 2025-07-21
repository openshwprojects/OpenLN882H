#ifndef _MQTT_DEMO_MUTUAL_H_
#define _MQTT_DEMO_MUTUAL_H_

#include "ln_types.h"

typedef void (*mqtt_connected_cb_t)(void);
typedef void (*mqtt_disconnected_cb_t)(void);
typedef void (*mqtt_incoming_pub_cb_t)(char* topic, uint16_t topic_len, char* message, uint16_t message_len);


typedef struct {
    const char *hostname;           /*!< Hostname, to set ipv4 pass it as string) */
    uint32_t    port;               /*!< *MQTT* server port */
   
    int         keepalive;          /*!< *MQTT* keepalive, default is 120 seconds */

    const char *client_id;          /*!< *MQTT* client identifier */
    const char *username;           /*!< *MQTT* username */
    const char *password;           /*!< *MQTT* password */

    const char *server_root_ca_pem;
    const char *client_cert_pem;
    const char *client_key_pem;

    const char *last_will_topic_name;
    const char *last_will_message;

    int                        is_connected;
    mqtt_connected_cb_t        connected_cb;
    mqtt_disconnected_cb_t     disconnected_cb;
    mqtt_incoming_pub_cb_t     incoming_pub_cb;
} mqtt_client_cfg_t;

int  __mqtt_cli_subscribe(const char* topic_filter, int qos);
int  __mqtt_cli_publish(const char* topic_filter, const char *data, int datalen, int qos, int retain);
int  __mqtt_cli_unsubscribe(const char* topic_filter);
void __mqtt_cli_conn(void);
void __mqtt_cli_disconn(void);

void creat_mqtt_task(mqtt_client_cfg_t *mqtt_client_cfg);

#endif
