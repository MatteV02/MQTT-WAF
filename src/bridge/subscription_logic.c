#include "bridge/subscription_logic.h"

// Global references for this module
static struct mosquitto *g_ext_client = NULL;
static mosquitto_plugin_id_t *g_plugin_id = NULL;

/* * Callback triggered when the external client receives a message.
 * We inject this message into the local broker.
 */
static void on_ext_client_message(struct mosquitto *client, void *userdata, const struct mosquitto_message *msg) {
    if (!msg || !msg->topic) {
        return;
    }

    // Publish the incoming external message directly to the local broker.
    // Using NULL for clientid indicates it was injected by the broker/plugin natively.
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

/* * Plugin callback triggered during ACL checks.
 * We use it to intercept local subscription requests.
 */
static int callback_acl_check(int event, void *event_data, void *userdata) {
    struct mosquitto_evt_acl_check *ed = (struct mosquitto_evt_acl_check *)event_data;

    // Check if the ACL request is specifically for a subscription attempt
    if (ed->access == MOSQ_ACL_SUBSCRIBE) {
        if (g_ext_client && ed->topic) {
            // Subscribe the external client to the identical topic locally requested
            mosquitto_subscribe(g_ext_client, NULL, ed->topic, 0);
            
            mosquitto_log_printf(MOSQ_LOG_INFO, 
                "Subscription Forwarder: Forwarded subscription for topic '%s' to external broker.", 
                ed->topic);
        }
    }

    // Always return SUCCESS so we don't interfere with the actual ACL evaluation
    return MOSQ_ERR_SUCCESS;
}

/* * Initialize the module by registering callbacks
 */
int init_subscription_logic(mosquitto_plugin_id_t *plugin_id, struct mosquitto *ext_client) {
    g_plugin_id = plugin_id;
    g_ext_client = ext_client;

    if (g_ext_client) {
        // Set the callback to process messages arriving from the external broker
        mosquitto_message_callback_set(g_ext_client, on_ext_client_message);
    }

    // Register the ACL check event to catch subscriptions on the local broker
    return mosquitto_callback_register(
        g_plugin_id, 
        MOSQ_EVT_ACL_CHECK, 
        callback_acl_check, 
        NULL, 
        NULL
    );
}

/* * Clean up the callbacks
 */
int cleanup_subscription_logic(mosquitto_plugin_id_t *plugin_id) {
    return mosquitto_callback_unregister(
        plugin_id, 
        MOSQ_EVT_ACL_CHECK, 
        callback_acl_check, 
        NULL
    );
}