#ifndef SUBSCRIPTION_LOGIC_H
#define SUBSCRIPTION_LOGIC_H

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

// Initializes the subscription forwarding logic
int init_subscription_logic(struct mosquitto *client);

void forward_subscription(struct mosquitto *client, const char *topic);

// Cleans up the registered callbacks
int cleanup_subscription_logic(struct mosquitto *client);

#endif // SUBSCRIPTION_LOGIC_H