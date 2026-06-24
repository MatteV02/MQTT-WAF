#include "bridge/subscription_logic.h"
#include <mosquitto.h>

/* Callback triggered when the external client receives a message. */
static void on_client_message(struct mosquitto *client, void *userdata, const struct mosquitto_message *msg) {
    if (!msg || !msg->topic) return;

    mosquitto_broker_publish_copy(
        NULL, 
        msg->topic,
        msg->payloadlen,
        msg->payload,
        msg->qos,
        msg->retain,
        NULL
    );
}

/* * Helper function to be called by the WAF ONLY AFTER a subscription is approved.
 */
void forward_subscription(struct mosquitto *client, const char *topic) {
    if (client && topic) {
        mosquitto_subscribe(client, NULL, topic, 0);
        mosquitto_log_printf(MOSQ_LOG_INFO, 
            "Subscription Forwarder: Forwarded WAF-approved subscription for topic '%s'", 
            topic);
    }
}

/* Initialize the module (Notice we no longer register the ACL callback here) */
int init_subscription_logic(struct mosquitto *client) {
    if (client) {
        mosquitto_message_callback_set(client, on_client_message);
    }
    return MOSQ_ERR_SUCCESS; 
}

/* Clean up */
int cleanup_subscription_logic(struct mosquitto *client) {
    if (client) {
        /* Unregister the message callback by passing NULL */
        mosquitto_message_callback_set(client, NULL);
    }

    return MOSQ_ERR_SUCCESS;
}