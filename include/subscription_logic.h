#ifndef SUBSCRIPTION_LOGIC_H
#define SUBSCRIPTION_LOGIC_H

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

// Initializes the subscription forwarding logic
int init_subscription_logic(mosquitto_plugin_id_t *plugin_id, struct mosquitto *ext_client);

// Cleans up the registered callbacks
int cleanup_subscription_logic(mosquitto_plugin_id_t *plugin_id);

#endif // SUBSCRIPTION_LOGIC_H