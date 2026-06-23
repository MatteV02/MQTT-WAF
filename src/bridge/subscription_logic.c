#include "bridge/subscription_logic.h"

static struct mosquitto *g_ext_client = NULL;
static mosquitto_plugin_id_t *g_plugin_id = NULL;

/* Callback triggered when the external client receives a message. */
static void on_ext_client_message(struct mosquitto *client, void *userdata, const struct mosquitto_message *msg) {
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
void forward_subscription(const char *topic) {
    if (g_ext_client && topic) {
        mosquitto_subscribe(g_ext_client, NULL, topic, 0);
        mosquitto_log_printf(MOSQ_LOG_INFO, 
            "Subscription Forwarder: Forwarded WAF-approved subscription for topic '%s'", 
            topic);
    }
}

/* Initialize the module (Notice we no longer register the ACL callback here) */
int init_subscription_logic(mosquitto_plugin_id_t *plugin_id, struct mosquitto *ext_client) {
    g_plugin_id = plugin_id;
    g_ext_client = ext_client;

    if (g_ext_client) {
        mosquitto_message_callback_set(g_ext_client, on_ext_client_message);
    }
    return MOSQ_ERR_SUCCESS; 
}

/* Clean up */
int cleanup_subscription_logic(mosquitto_plugin_id_t *plugin_id) {
    // Nothing to unregister anymore
    return MOSQ_ERR_SUCCESS;
}