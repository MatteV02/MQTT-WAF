/**
 * @file message_forwarder.c
 * @brief MQTT message logging utility for Mosquitto broker plugins.
 *
 * @defgroup message_forwarder
 * @brief Code unit for forwarding inbound and outbound communication through an external broker.
 * @ingroup bridge
 * 
 * @{
 */

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

/* ---------------------------------------------------------
 * INTERNAL HELPER
 * --------------------------------------------------------- */
static struct mosquitto * _init_client(const char* client_id, const char *host, int port, const char* role) {
    struct mosquitto * client = mosquitto_new(client_id, true, NULL);
    if (!client) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Bridge: Failed to create %s client (%s)", role, client_id);
        return NULL;
    }

    int rc = mosquitto_connect_async(client, host, port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Bridge: Failed to connect %s to external broker", role);
    } else {
        mosquitto_loop_start(client);
        mosquitto_log_printf(MOSQ_LOG_INFO, "Bridge: %s started %s (%s:%d)", role, client_id, host, port);
    }
    return client;
}

/* ---------------------------------------------------------
 * PUBLISHER LIFECYCLE
 * --------------------------------------------------------- */
struct mosquitto * start_publish_forwarder(const char* client_id, const char *host, int port) {
    return _init_client(client_id, host, port, "Publisher");
}

void stop_publish_forwarder(struct mosquitto ** ext_client_ptr) {
    if (ext_client_ptr && *ext_client_ptr) {
        struct mosquitto *ext_client = *ext_client_ptr;
        mosquitto_disconnect(ext_client);
        mosquitto_loop_stop(ext_client, true); 
        mosquitto_destroy(ext_client);
        *ext_client_ptr = NULL; 
    }
}

/* ---------------------------------------------------------
 * SUBSCRIBER LIFECYCLE
 * --------------------------------------------------------- */
struct mosquitto * start_subscription_forwarder(const char* client_id, const char *host, int port) {
    struct mosquitto * client = _init_client(client_id, host, port, "Subscriber");
    if (client) {
        // Attach the listener callback only to the subscriber
        mosquitto_message_callback_set(client, on_subscription_message_received);
    }
    return client;
}

void stop_subscription_forwarder(struct mosquitto ** ext_client_ptr) {
    if (ext_client_ptr && *ext_client_ptr) {
        struct mosquitto *ext_client = *ext_client_ptr;
        mosquitto_message_callback_set(ext_client, NULL);
        mosquitto_disconnect(ext_client);
        mosquitto_loop_stop(ext_client, true); 
        mosquitto_destroy(ext_client);
        *ext_client_ptr = NULL; 
    }
}

/** @} */