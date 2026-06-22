#ifndef SETTINGS_H_
#define SETTINGS_H_

struct settings {
    char* ext_broker_host;
    int ext_broker_port;
    char* ext_client_id;
};

/* Parses the YAML file and populates the struct */
struct settings* parse_settings(const char* filename);

/* Frees the dynamically allocated strings inside the struct */
void free_settings(struct settings* cfg);

#endif // SETTINGS_H_