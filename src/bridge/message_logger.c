/**
 * @file message_logger.c
 * @brief Implementation of the MQTT message logging utility.
 *
 * @defgroup message_logger
 * @brief MQTT message logging utility for Mosquitto broker plugins.
 * @ingroup bridge
 * 
 * @{
 */

#include <stdio.h>
#include "bridge/message_logger.h"

FILE *log_file = NULL;

int start_logger() {
    log_file = fopen("/tmp/mqtt_packets.log", "a");

    return log_file ? 0 : -1;
}

void log_message(struct mosquitto_evt_acl_check* msg) {
    if (log_file && msg && msg->topic) {
        fprintf(log_file, "Topic: %s | QoS: %d | Retain: %d | Payload Length: %d\n", 
                msg->topic, msg->qos, msg->retain, msg->payloadlen);
        
        if (msg->payloadlen > 0 && msg->payload) {
            fprintf(log_file, "Payload: ");
            // Write payload directly. Note: if the payload is purely binary, 
            // this will write raw binary bytes to the text file.
            fwrite(msg->payload, 1, msg->payloadlen, log_file);
            fprintf(log_file, "\n");
        }
        
        fprintf(log_file, "--------------------------------------------------\n");
        fflush(log_file); // Flush immediately to ensure data is written to disk
    }
}

void stop_logger() {
    // Safely close the file handle
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

/** @} */