/**
 * @file message_forwarder.h
 * @brief Code unit for forwarding inbound and outbound communication through an external broker.
 */

#ifndef MESSAGE_FORWARDER_H_
#define MESSAGE_FORWARDER_H_

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

/**
 * @brief Intitialize a Mosquitto client, connect to a certain host and port and set it up to forward messages in input and output.
 * @param client_id String id of the client
 * @param host hostname/ip of the destination
 * @param port port number
 * @return Pointer to the Mosquitto client, NULL if initialization fails.
 */
struct mosquitto * start_forwarder(char* client_id, char* host, int port);

/**
 * @brief Forward outgoing messages.
 * 
 * @param ext_client Mosquitto client
 * @param msg Message object (mosquitto_evt_acl_check from Mosquitto API)
 * @return same as mosquitto_publish
 * - MOSQ_ERR_SUCCESS - on success.
 * - MOSQ_ERR_INVAL - if the input parameters were invalid.
 * - MOSQ_ERR_NOMEM - if an out of memory condition occurred.
 * - MOSQ_ERR_NO_CONN - if the client isn't connected to a broker.
 * - MOSQ_ERR_PROTOCOL - if there is a protocol error communicating with the broker.
 * - MOSQ_ERR_PAYLOAD_SIZE - if payloadlen is too large.
 * - MOSQ_ERR_MALFORMED_UTF8 - if the topic is not valid UTF-8 MOSQ_ERR_QOS_NOT_SUPPORTED - if the QoS is greater than that supported by the broker.
 * - MOSQ_ERR_OVERSIZE_PACKET - if the resulting packet would be larger than supported by the broker.
 */
int publish_forward(struct mosquitto *ext_client, struct mosquitto_evt_acl_check* msg);

/**
 * @brief Forward subscription requests.
 * 
 * @param ext_client Mosquitto client
 * @param topic Topic to subscribe
 * @return same as mosquitto_subscribe
 * - MOSQ_ERR_SUCCESS - on success.
 * - MOSQ_ERR_INVAL - if the input parameters were invalid.
 * - MOSQ_ERR_NOMEM - if an out of memory condition occurred.
 * - MOSQ_ERR_NO_CONN - if the client isn't connected to a broker.
 * - MOSQ_ERR_MALFORMED_UTF8 - if the topic is not valid UTF-8 MOSQ_ERR_OVERSIZE_PACKET - if the resulting packet would be larger than supported by the broker.
 */
int subscription_forward(struct mosquitto *ext_client, const char *topic);

/**
 * @brief Free mosquitto client initialized with start_forwarder.
 * 
 * @param ext_client Mosquitto client
 */
void stop_forwarder(struct mosquitto * ext_client);

#endif