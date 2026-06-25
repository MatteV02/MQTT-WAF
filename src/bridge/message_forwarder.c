#include "bridge/message_forwarder.h"

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <string.h>

int publish_forward(struct mosquitto *ext_client, struct mosquitto_evt_acl_check* msg) {
    if (ext_client && msg && msg->topic) {
        
        // Ignore internal $SYS topics to prevent spamming the external broker
        if (strncmp(msg->topic, "$SYS", 4) == 0) {
            return 0;
        }

        // Publish the payload to the external broker
        // mosquitto_publish is thread-safe and non-blocking when used with mosquitto_loop_start()
        int rc = mosquitto_publish(ext_client, 
                                    NULL,            // message id (not needed)
                                    msg->topic,      // same topic
                                    msg->payloadlen, // same length
                                    msg->payload,    // same payload
                                    msg->qos,        // same QoS
                                    msg->retain);    // same retain flag
                                    
        if (rc != MOSQ_ERR_SUCCESS) {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to forward msg on %s (Error: %d)", msg->topic, rc);
            return -1;
        }
    } else {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to forward msg on (no connection)");
        return -1;
    }

    return 0;
}

/* * Helper function to be called by the WAF ONLY AFTER a subscription is approved.
 */
int subscription_forward(struct mosquitto *client, const char *topic) {
    int rc = MOSQ_ERR_UNKNOWN;
    if (client && topic) {
        rc = mosquitto_subscribe(client, NULL, topic, 0);
        if (rc == MOSQ_ERR_SUCCESS) {
            mosquitto_log_printf(MOSQ_LOG_INFO, 
                "Subscription Forwarder: Forwarded WAF-approved subscription for topic '%s'", 
                topic);
        } else {
            mosquitto_log_printf(MOSQ_LOG_WARNING, 
                "Subscription Forwarder: Forwarded WAF-subscription failed for topic '%s'", 
                topic);
        }
    }

    return rc;
}

/* Callback triggered when the external client receives a message. */
static void on_subscription_message_received(struct mosquitto *client, void *userdata, const struct mosquitto_message *msg) {
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

struct mosquitto * start_forwarder(char* client_id, char *host, int port) {
    mosquitto_lib_init();
    
    struct mosquitto * ext_client = mosquitto_new(client_id, true, NULL);
    if (!ext_client) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to create external MQTT client");
        return ext_client;
    }

    int rc = mosquitto_connect_async(ext_client, host, port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Logger Plugin: Failed to init connection to external broker");
    } else {
        // mosquitto_loop_start creates a background thread to handle network I/O
        mosquitto_loop_start(ext_client);
        mosquitto_log_printf(MOSQ_LOG_INFO, "Logger Plugin: Forwarder started (%s:%d)", host, port);
    }

    // start subscription listener
    if (ext_client) {
        mosquitto_message_callback_set(ext_client, on_subscription_message_received);
    }

    return ext_client;
}

void stop_forwarder(struct mosquitto * ext_client) {
    if (ext_client) {
        /* Unregister the message callback by passing NULL */
        mosquitto_message_callback_set(ext_client, NULL);
        mosquitto_disconnect(ext_client);
        mosquitto_loop_stop(ext_client, true); // wait for the network thread to finish gracefully
        mosquitto_destroy(ext_client);
        ext_client = NULL;
    }
    mosquitto_lib_cleanup();
}