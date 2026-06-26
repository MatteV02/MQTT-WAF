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
#include <pthread.h>
#include "bridge/message_logger.h"

FILE *log_file = NULL;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

int start_logger() {
    log_file = fopen("/tmp/mqtt_packets.log", "a");

    return log_file ? 0 : -1;
}

void log_message(struct mosquitto_evt_acl_check* msg) {
    if (log_file && msg && msg->topic) {
        pthread_mutex_lock(&log_mutex);

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

        pthread_mutex_unlock(&log_mutex); // Unlock after flushing
    }
}

void stop_logger() {
    // Safely close the file handle
    pthread_mutex_lock(&log_mutex);
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    pthread_mutex_unlock(&log_mutex);
}

/** @} */