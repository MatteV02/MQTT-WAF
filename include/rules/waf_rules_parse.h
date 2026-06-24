#ifndef WAF_RULES_PARSE_H_
#define WAF_RULES_PARSE_H_

#include <stdbool.h>
#include <regex.h>

/* ---------------------------------------------------------
 * WAF DATA STRUCTURES
 * --------------------------------------------------------- */

struct default_policies {
    char *connection;
    char *authentication;
    char *publish;
    char *subscribe;
};

struct connection_rule {
    char *id;
    char *name;
    char *action;
    char *ip_range;         
    char *client_id_regex;  
    regex_t compiled_client_id_regex; /* NEW: Compiled regex */
    bool has_client_id_regex;         /* NEW: Compilation flag */
    bool require_tls;       
    char **ip_list;         
    unsigned ip_list_count;
};

struct auth_trigger {
    int max_failed_attempts;
    char *time_window;
};

struct auth_enforcement {
    char *lockout_duration;
    char *target;
};

struct authentication_rule {
    char *id;
    char *name;
    char *action;
    struct auth_trigger trigger;
    struct auth_enforcement enforcement;
};

struct message_rule {
    char *id;
    char *name;
    char *action;
    char **topics;
    unsigned topics_count;
    char *payload_regex;
    regex_t compiled_payload_regex; /* NEW: Compiled regex */
    bool has_payload_regex;         /* NEW: Compilation flag */
    bool log;               
    bool invert_match;      
};

struct topic_permissions {
    char **publish;         
    unsigned publish_count;
    char **subscribe;       
    unsigned subscribe_count;
};

struct topic_rule {
    char *id;
    char *name;
    char *action;
    char *client_id_regex;
    regex_t compiled_client_id_regex; /* NEW: Compiled regex */
    bool has_client_id_regex;         /* NEW: Compilation flag */
    struct topic_permissions permissions;
};

struct rate_quota {
    int max_messages;
    char *time_window;
};

struct rate_limiting_rule {
    char *id;
    char *name;
    char *action;
    char *client_id_regex;  
    regex_t compiled_client_id_regex; /* NEW: Compiled regex */
    bool has_client_id_regex;         /* NEW: Compilation flag */
    char *packet_type;      
    char *ip_range;          
    struct rate_quota quota;
};

/* Wrapper containing all rule categories separated in arrays */
struct rules_section {
    struct connection_rule *connection;
    unsigned connection_count;
    struct authentication_rule *authentication;
    unsigned authentication_count;
    struct message_rule *message;
    unsigned message_count;
    struct topic_rule *topic;
    unsigned topic_count;
    struct rate_limiting_rule *rate_limiting;
    unsigned rate_limiting_count;
};

/* Top-level Configuration Node */
struct waf_config {
    char *version;
    struct default_policies default_policies;
    struct rules_section rules;
};

/* ---------------------------------------------------------
 * FUNCTION PROTOTYPES
 * --------------------------------------------------------- */

/**
 * Loads the WAF YAML rules file into dynamically allocated C arrays.
 * @param filepath Path to the YAML rule definitions file.
 * @return Struct pointer containing separate rule arrays, or NULL on failure.
 */
struct waf_config* load_waf_rules(const char *filepath);

/**
 * Cleanly frees all memory allocations generated during the parsing process.
 * Call this inside mosquitto_plugin_cleanup.
 * @param config Pointer to the loaded waf_config struct.
 */
void free_waf_rules(struct waf_config *config);

void print_waf_rules(struct waf_config *config);

#endif /* WAF_RULES_PARSE_H_ */