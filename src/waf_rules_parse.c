#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <cyaml/cyaml.h>

#include "waf_rules_parse.h"

/* ---------------------------------------------------------
 * LIBCYAML SCHEMAS
 * --------------------------------------------------------- */

/* Schema for lists of strings (e.g., ip_list, topics) */
static const cyaml_schema_value_t string_schema = {
    CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED)
};

/* 1) Connection Rules Schema */
static const cyaml_schema_field_t connection_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER, struct connection_rule, id, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct connection_rule, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("action", CYAML_FLAG_POINTER, struct connection_rule, action, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("ip_range", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct connection_rule, ip_range, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("client_id_regex", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct connection_rule, client_id_regex, 0, CYAML_UNLIMITED),
    CYAML_FIELD_BOOL("require_tls", CYAML_FLAG_OPTIONAL, struct connection_rule, require_tls),
    CYAML_FIELD_SEQUENCE_COUNT("ip_list", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct connection_rule, ip_list, ip_list_count, &string_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t connection_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct connection_rule, connection_fields_schema)
};

/* 2) Authentication Rules Schema */
static const cyaml_schema_field_t auth_trigger_fields[] = {
    CYAML_FIELD_INT("max_failed_attempts", CYAML_FLAG_DEFAULT, struct auth_trigger, max_failed_attempts),
    CYAML_FIELD_STRING_PTR("time_window", CYAML_FLAG_POINTER, struct auth_trigger, time_window, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t auth_enforcement_fields[] = {
    CYAML_FIELD_STRING_PTR("lockout_duration", CYAML_FLAG_POINTER, struct auth_enforcement, lockout_duration, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("target", CYAML_FLAG_POINTER, struct auth_enforcement, target, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t authentication_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER, struct authentication_rule, id, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct authentication_rule, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("action", CYAML_FLAG_POINTER, struct authentication_rule, action, 0, CYAML_UNLIMITED),
    CYAML_FIELD_MAPPING("trigger", CYAML_FLAG_DEFAULT, struct authentication_rule, trigger, auth_trigger_fields),
    CYAML_FIELD_MAPPING("enforcement", CYAML_FLAG_DEFAULT, struct authentication_rule, enforcement, auth_enforcement_fields),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t authentication_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct authentication_rule, authentication_fields_schema)
};

/* 3) Message Rules Schema */
static const cyaml_schema_field_t message_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER, struct message_rule, id, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct message_rule, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("action", CYAML_FLAG_POINTER, struct message_rule, action, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("topics", CYAML_FLAG_POINTER, struct message_rule, topics, topics_count, &string_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("payload_regex", CYAML_FLAG_POINTER, struct message_rule, payload_regex, 0, CYAML_UNLIMITED),
    CYAML_FIELD_BOOL("log", CYAML_FLAG_OPTIONAL, struct message_rule, log),
    CYAML_FIELD_BOOL("invert_match", CYAML_FLAG_OPTIONAL, struct message_rule, invert_match),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t message_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct message_rule, message_fields_schema)
};

/* 4) Topic Rules Schema */
static const cyaml_schema_field_t topic_permissions_fields[] = {
    CYAML_FIELD_SEQUENCE_COUNT("publish", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct topic_permissions, publish, publish_count, &string_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("subscribe", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct topic_permissions, subscribe, subscribe_count, &string_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t topic_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER, struct topic_rule, id, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct topic_rule, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("action", CYAML_FLAG_POINTER, struct topic_rule, action, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("client_id_regex", CYAML_FLAG_POINTER, struct topic_rule, client_id_regex, 0, CYAML_UNLIMITED),
    CYAML_FIELD_MAPPING("permissions", CYAML_FLAG_DEFAULT, struct topic_rule, permissions, topic_permissions_fields),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t topic_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct topic_rule, topic_fields_schema)
};

/* 5) Rate-Limiting Rules Schema */
static const cyaml_schema_field_t rate_quota_fields[] = {
    CYAML_FIELD_INT("max_messages", CYAML_FLAG_DEFAULT, struct rate_quota, max_messages),
    CYAML_FIELD_STRING_PTR("time_window", CYAML_FLAG_POINTER, struct rate_quota, time_window, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t rate_limiting_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER, struct rate_limiting_rule, id, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct rate_limiting_rule, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("action", CYAML_FLAG_POINTER, struct rate_limiting_rule, action, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("client_id_regex", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rate_limiting_rule, client_id_regex, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("packet_type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rate_limiting_rule, packet_type, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("ip_range", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rate_limiting_rule, ip_range, 0, CYAML_UNLIMITED),
    CYAML_FIELD_MAPPING("quota", CYAML_FLAG_DEFAULT, struct rate_limiting_rule, quota, rate_quota_fields),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t rate_limiting_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct rate_limiting_rule, rate_limiting_fields_schema)
};

/* Rules Object Schema Grouping Arrays Together */
static const cyaml_schema_field_t rules_section_fields[] = {
    CYAML_FIELD_SEQUENCE_COUNT("connection", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rules_section, connection, connection_count, &connection_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("authentication", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rules_section, authentication, authentication_count, &authentication_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("message", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rules_section, message, message_count, &message_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("topic", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rules_section, topic, topic_count, &topic_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("rate_limiting", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rules_section, rate_limiting, rate_limiting_count, &rate_limiting_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

/* Global and Defaults Policies Schema */
static const cyaml_schema_field_t default_policies_fields[] = {
    CYAML_FIELD_STRING_PTR("connection", CYAML_FLAG_POINTER, struct default_policies, connection, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("authentication", CYAML_FLAG_POINTER, struct default_policies, authentication, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("publish", CYAML_FLAG_POINTER, struct default_policies, publish, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("subscribe", CYAML_FLAG_POINTER, struct default_policies, subscribe, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

/* Root Configuration Schema Mapping */
static const cyaml_schema_field_t top_level_fields[] = {
    CYAML_FIELD_STRING_PTR("version", CYAML_FLAG_POINTER, struct waf_config, version, 0, CYAML_UNLIMITED),
    CYAML_FIELD_MAPPING("default_policies", CYAML_FLAG_DEFAULT, struct waf_config, default_policies, default_policies_fields),
    CYAML_FIELD_MAPPING("rules", CYAML_FLAG_DEFAULT, struct waf_config, rules, rules_section_fields),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t top_level_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct waf_config, top_level_fields)
};

static void waf_cyaml_log(cyaml_log_t level, void *ctx, const char *fmt, va_list args) {
    // Default to stderr if ctx is NULL
    FILE *out = (ctx != NULL) ? (FILE *)ctx : stderr;
    
    // Optional: Add a prefix so you know it came from the WAF parser
    fprintf(out, "[WAF Parser] ");
    vfprintf(out, fmt, args);
}

/* libcyaml Logging & Allocator Config */
static const cyaml_config_t cyaml_config = {
    .log_fn = waf_cyaml_log,
    .log_ctx = NULL,
    .log_level = CYAML_LOG_WARNING,
    .mem_fn = cyaml_mem,
};


/**
 * Loads the WAF YAML rules file into dynamically allocated C arrays.
 * * @param filepath Path to the YAML rule definitions file.
 * @return Struct pointer containing separate rule arrays, or NULL on failure.
 */
struct waf_config* load_waf_rules(const char *filepath) {
    struct waf_config *config = NULL;

    cyaml_err_t err = cyaml_load_file(filepath, &cyaml_config, 
                                      &top_level_schema, 
                                      (cyaml_data_t **)&config, NULL);

    if (err != CYAML_OK) {
        fprintf(stderr, "[WAF ERROR] Failed to parse rule file %s: %s\n", 
                filepath, cyaml_strerror(err));
        return NULL;
    }

    return config;
}

/**
 * Cleanly frees all memory allocations generated during the parsing process.
 * Call this inside mosquitto_plugin_cleanup.
 */
void free_waf_rules(struct waf_config *config) {
    if (config != NULL) {
        cyaml_free(&cyaml_config, &top_level_schema, config, 0);
    }
}


/* ---------------------------------------------------------
 * HELPER: PRINT WAF RULES TO STDOUT
 * --------------------------------------------------------- */
void print_waf_rules(struct waf_config *config) {
    if (!config) return;

    printf("\n=========================================\n");
    printf("         WAF CONFIGURATION LOADED        \n");
    printf("=========================================\n");
    printf("Version: %s\n\n", config->version ? config->version : "Unknown");

    printf("[Default Policies]\n");
    printf("  Connection: %s\n", config->default_policies.connection);
    printf("  Auth:       %s\n", config->default_policies.authentication);
    printf("  Publish:    %s\n", config->default_policies.publish);
    printf("  Subscribe:  %s\n\n", config->default_policies.subscribe);

    printf("[Connection Rules] Count: %u\n", config->rules.connection_count);
    for (unsigned i = 0; i < config->rules.connection_count; i++) {
        struct connection_rule *r = &config->rules.connection[i];
        printf("  - %s [%s] -> %s\n", r->id, r->name, r->action);
    }

    printf("\n[Authentication Rules] Count: %u\n", config->rules.authentication_count);
    for (unsigned i = 0; i < config->rules.authentication_count; i++) {
        struct authentication_rule *r = &config->rules.authentication[i];
        printf("  - %s [%s] -> %s (Lockout: %s)\n", r->id, r->name, r->action, r->enforcement.lockout_duration);
    }

    printf("\n[Message Rules] Count: %u\n", config->rules.message_count);
    for (unsigned i = 0; i < config->rules.message_count; i++) {
        struct message_rule *r = &config->rules.message[i];
        printf("  - %s [%s] -> %s\n", r->id, r->name, r->action);
        printf("      Regex: %s\n", r->payload_regex);
    }

    printf("\n[Topic Rules] Count: %u\n", config->rules.topic_count);
    for (unsigned i = 0; i < config->rules.topic_count; i++) {
        struct topic_rule *r = &config->rules.topic[i];
        printf("  - %s [%s] -> %s\n", r->id, r->name, r->action);
    }

    printf("\n[Rate Limiting Rules] Count: %u\n", config->rules.rate_limiting_count);
    for (unsigned i = 0; i < config->rules.rate_limiting_count; i++) {
        struct rate_limiting_rule *r = &config->rules.rate_limiting[i];
        printf("  - %s [%s] -> %s (Max: %d per %s)\n", r->id, r->name, r->action, r->quota.max_messages, r->quota.time_window);
    }
    printf("=========================================\n\n");
    
    // Force flush stdout in case Mosquitto is running as a background daemon
    fflush(stdout); 
}
