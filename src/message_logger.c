#include "message_logger.h"

FILE *log_file = NULL;

void log_message(struct mosquitto_evt_message* msg) {
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