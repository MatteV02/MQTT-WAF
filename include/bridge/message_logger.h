/**
 * @file message_logger.h
 * @brief MQTT message logging utility for Mosquitto broker plugins.
 * * This module provides a simple interface to initialize a log file, 
 * write MQTT message details (such as topic, QoS, retain flag, and payload) 
 * to disk, and safely clean up the file handles.
 * @defgroup message_logger
 * @brief MQTT message logging utility for Mosquitto broker plugins.
 * @ingroup bridge
 * 
 * @{
 */

#ifndef MESSAGE_LOGGER_H_
#define MESSAGE_LOGGER_H_

#include <mosquitto_broker.h>

/**
 * @brief Initializes the message logger.
 * * Opens the log file (typically "/tmp/mqtt_packets.log") in append mode.
 * * @return 0 on successful initialization, -1 if the log file cannot be opened.
 */
void log_message(struct mosquitto_evt_acl_check* msg);

/**
 * @brief Logs the details of an MQTT message to the log file.
 * * Extracts the topic, QoS, retain flag, payload length, and raw payload 
 * from the provided Mosquitto event structure. The data is written to the 
 * file and the stream is flushed immediately to ensure persistence.
 * * @param msg Pointer to the mosquitto_evt_acl_check structure containing 
 * the intercepted message data. Safe to pass NULL (it will be ignored).
 */
int start_logger();

/**
 * @brief Stops the logger and cleans up resources.
 * * Safely closes the log file handle if it is currently open and resets 
 * the file pointer to NULL.
 */
void stop_logger();

#endif

/** @} */