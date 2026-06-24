#ifndef MESSAGE_FORWARDER_H_
#define MESSAGE_FORWARDER_H_

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>

struct mosquitto * start_forwarder(char* client_id, char* host, int port);
int forward_message(struct mosquitto *ext_client, struct mosquitto_evt_acl_check* msg);
void stop_forwarder(struct mosquitto * ext_client);

#endif