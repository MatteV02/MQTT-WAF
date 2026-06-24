#include "bridge/message_forwarder.h"

#include <mosquitto.h>
#include <string.h>

int forward_message(struct mosquitto *ext_client, struct mosquitto_evt_message* msg) {
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

    return ext_client;
}

void stop_forwarder(struct mosquitto * ext_client) {
    if (ext_client) {
        mosquitto_disconnect(ext_client);
        mosquitto_loop_stop(ext_client, true); // wait for the network thread to finish gracefully
        mosquitto_destroy(ext_client);
        ext_client = NULL;
    }
    mosquitto_lib_cleanup();
}