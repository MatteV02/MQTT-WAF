#ifndef MESSAGE_FORWARDER_H_
#define MESSAGE_FORWARDER_H_

#include <mosquitto.h>
#include <mosquitto_plugin.h>

struct mosquitto * start_forwarder(char* client_id, char* host, int port);
int forward_message(struct mosquitto *ext_client, struct mosquitto_evt_message* msg);
void stop_forwarder(struct mosquitto * ext_client);

#endif