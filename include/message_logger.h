#ifndef MESSAGE_LOGGER_H_
#define MESSAGE_LOGGER_H_

#include <stdio.h>
#include <mosquitto_broker.h>

extern FILE *log_file;

void log_message(struct mosquitto_evt_message* msg);
int start_logger();
void stop_logger();

#endif