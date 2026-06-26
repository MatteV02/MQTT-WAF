/**
 * @file waf_rules_parse.h
 * @brief WAF rules parsing data structures and function prototypes.
 *
 * @ingroup waf_rules_parse
 */

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <cyaml/cyaml.h>
#include <regex.h>
#include <string.h>
#include <mosquitto_plugin.h>

#include "rules/waf_rules_parse.h"

/* ---------------------------------------------------------
 * LIBCYAML SCHEMAS
 * --------------------------------------------------------- */

/* Schema for lists of strings (e.g., ip_list, topics) */
static const cyaml_schema_value_t string_schema = {
    CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED)
};

/* 3) Message Rules Schema */
static const cyaml_schema_field_t message_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER, struct message_rule, id, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct message_rule, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("action", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct message_rule, action, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("topics", CYAML_FLAG_POINTER, struct message_rule, topics, topics_count, &string_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("payload_regex", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct message_rule, payload_regex, 0, CYAML_UNLIMITED),
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
    CYAML_FIELD_STRING_PTR("action", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct topic_rule, action, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("client_id_regex", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct topic_rule, client_id_regex, 0, CYAML_UNLIMITED),
    CYAML_FIELD_MAPPING("permissions", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct topic_rule, permissions, topic_permissions_fields),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t topic_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct topic_rule, topic_fields_schema)
};

/* Rules Object Schema Grouping Arrays Together */
static const cyaml_schema_field_t rules_section_fields[] = {
    CYAML_FIELD_SEQUENCE_COUNT("message", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rules_section, message, message_count, &message_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("topic", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct rules_section, topic, topic_count, &topic_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

/* Global and Defaults Policies Schema */
static const cyaml_schema_field_t default_policies_fields[] = {
    CYAML_FIELD_STRING_PTR("publish", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct default_policies, publish, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("subscribe", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct default_policies, subscribe, 0, CYAML_UNLIMITED),
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

/**
 * @brief Custom logger callback for libcyaml operations.
 * * @param level The severity level of the log message.
 * @param ctx Context pointer (typically a file pointer like stderr).
 * @param fmt Format string for the log message.
 * @param args Variadic arguments for the format string.
 */
static void waf_cyaml_log(cyaml_log_t level, void *ctx, const char *fmt, va_list args) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "[WAF Parser] ");
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    mosquitto_log_printf(MOSQ_LOG_ERR, "%s", buf);
}

/* libcyaml Logging & Allocator Config */
static const cyaml_config_t cyaml_config = {
    .log_fn = waf_cyaml_log,
    .log_ctx = NULL,
    .log_level = CYAML_LOG_WARNING,
    .mem_fn = cyaml_mem,
};


/* ---------------------------------------------------------
 * HELPER: REGEX COMPILER
 * --------------------------------------------------------- */

/**
 * @brief Helper to safely compile a single regex pattern.
 * * @param compiled Pointer to the regex_t structure where the compiled result will be stored.
 * @param pattern The raw regular expression string.
 * @param rule_id The ID of the rule (used for error logging).
 * @param rule_type The type/category of the rule (used for error logging).
 * @return true if compilation was successful, false otherwise.
 */
static bool compile_single_regex(regex_t *compiled, const char *pattern, const char *rule_id, const char *rule_type) {
    /* REG_EXTENDED for modern regex syntax, REG_NOSUB because we don't need extraction */
    int err = regcomp(compiled, pattern, REG_EXTENDED | REG_NOSUB);
    if (err != 0) {
        char errbuf[256];
        regerror(err, compiled, errbuf, sizeof(errbuf));
        mosquitto_log_printf(MOSQ_LOG_ERR, "[WAF ERROR] Failed to compile regex '%s' for %s rule '%s': %s\n",
                pattern, rule_type, rule_id ? rule_id : "unknown", errbuf);
        return false;
    }
    return true;
}

/**
 * @brief Iterates over all parsed rules and compiles their regular expressions.
 * * Validates and compiles `client_id_regex` and `payload_regex` fields across all rules.
 * * @param config Pointer to the fully loaded waf_config struct.
 * @return 0 on success, -1 if any regular expression fails to compile.
 */
static int compile_rule_regexes(struct waf_config *config) {
    /* Initialize all has_regex flags to false first, ensuring safe cleanup if we fail halfway */
    for (unsigned i = 0; i < config->rules.message_count; i++)    config->rules.message[i].has_payload_regex = false;
    for (unsigned i = 0; i < config->rules.topic_count; i++)      config->rules.topic[i].has_client_id_regex = false;

    /* Compile Message Regexes */
    for (unsigned i = 0; i < config->rules.message_count; i++) {
        struct message_rule *r = &config->rules.message[i];
        if (r->payload_regex) {
            if (!compile_single_regex(&r->compiled_payload_regex, r->payload_regex, r->id, "message")) return -1;
            r->has_payload_regex = true;
        }
    }

    /* Compile Topic Regexes */
    for (unsigned i = 0; i < config->rules.topic_count; i++) {
        struct topic_rule *r = &config->rules.topic[i];
        if (r->client_id_regex) {
            if (!compile_single_regex(&r->compiled_client_id_regex, r->client_id_regex, r->id, "topic")) return -1;
            r->has_client_id_regex = true;
        }
    }

    return 0;
}

/* ---------------------------------------------------------
 * HELPER: APPLY DEFAULT VALUES
 * --------------------------------------------------------- */

/**
 * @brief Hydrates missing optional fields in the config structure with system defaults.
 * * @param config Pointer to the fully loaded waf_config struct.
 */
 static int apply_default_values(struct waf_config *config) {
    if (!config) return -1;

    /* Global Defaults */
    if (!config->default_policies.publish)      config->default_policies.publish = strdup("allow");
    if (!config->default_policies.publish)      return -1;
    if (!config->default_policies.subscribe)    config->default_policies.subscribe = strdup("allow");
    if (!config->default_policies.subscribe)    return -1;

    /* Message Rules */
    for (unsigned i = 0; i < config->rules.message_count; i++) {
        struct message_rule *r = &config->rules.message[i];
        if (!r->action) r->action = strdup("allow");
        if (!r->action) return -1;

        // r->payload_regex defaults to NULL. We leave it as NULL. 
        // Our compile_rule_regexes() function already checks `if (r->payload_regex)` 
        // so it will safely skip compilation for rules without regexes.

        // r->log and r->invert_match default to `false` via libcyaml zero-init.
    }

    /* Topic Rules */
    for (unsigned i = 0; i < config->rules.topic_count; i++) {
        struct topic_rule *r = &config->rules.topic[i];
        if (!r->action) r->action = strdup("allow");
        if (!r->action) return -1;

        // r->permissions mapping: 
        // If omitted, publish_count and subscribe_count are naturally 0, 
        // and their string arrays are NULL. This safely evaluates to "no explicit permissions defined".
    }

    return 0;
}

/* ---------------------------------------------------------
 * CORE PARSING FUNCTIONS
 * --------------------------------------------------------- */

struct waf_config* load_waf_rules(const char *filepath) {
    struct waf_config *config = NULL;

    cyaml_err_t err = cyaml_load_file(filepath, &cyaml_config, 
                                      &top_level_schema, 
                                      (cyaml_data_t **)&config, NULL);

    if (err != CYAML_OK) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "[WAF ERROR] Failed to parse rule file %s: %s\n", 
                filepath, cyaml_strerror(err));
        return NULL;
    }

    /* Apply default values */
    if (apply_default_values(config)) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "[WAF ERROR] Failed to apply default values.\n");
        free_waf_rules(config);
        return NULL;
    }

    /* Compile Regexes Post-Parse */
    if (compile_rule_regexes(config) != 0) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "[WAF ERROR] Failed to compile regex.\n");
        free_waf_rules(config);
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
        
        /* 1) Free Compiled Regexes */
        for (unsigned i = 0; i < config->rules.message_count; i++) {
            if (config->rules.message[i].has_payload_regex) regfree(&config->rules.message[i].compiled_payload_regex);
        }
        for (unsigned i = 0; i < config->rules.topic_count; i++) {
            if (config->rules.topic[i].has_client_id_regex) regfree(&config->rules.topic[i].compiled_client_id_regex);
        }

        /* 2) Free Struct Memory Allocated by CYAML */
        cyaml_free(&cyaml_config, &top_level_schema, config, 0);
    }
}


/* ---------------------------------------------------------
 * HELPER: PRINT WAF RULES TO STDOUT
 * --------------------------------------------------------- */
void print_waf_rules(struct waf_config *config) {
    if (!config) return;

    mosquitto_log_printf(MOSQ_LOG_INFO, "\n=========================================\n");
    mosquitto_log_printf(MOSQ_LOG_INFO, "         WAF CONFIGURATION LOADED        \n");
    mosquitto_log_printf(MOSQ_LOG_INFO, "=========================================\n");
    mosquitto_log_printf(MOSQ_LOG_INFO, "Version: %s\n\n", config->version ? config->version : "Unknown");

    mosquitto_log_printf(MOSQ_LOG_INFO, "[Default Policies]\n");
    mosquitto_log_printf(MOSQ_LOG_INFO, "  Publish:    %s\n", config->default_policies.publish);
    mosquitto_log_printf(MOSQ_LOG_INFO, "  Subscribe:  %s\n\n", config->default_policies.subscribe);

    mosquitto_log_printf(MOSQ_LOG_INFO, "\n[Message Rules] Count: %u\n", config->rules.message_count);
    for (unsigned i = 0; i < config->rules.message_count; i++) {
        struct message_rule *r = &config->rules.message[i];
        mosquitto_log_printf(MOSQ_LOG_INFO, "  - %s [%s] -> %s\n", r->id, r->name, r->action);
        mosquitto_log_printf(MOSQ_LOG_INFO, "      Regex: %s (Compiled: %s)\n", r->payload_regex, r->has_payload_regex ? "Yes" : "No");
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "\n[Topic Rules] Count: %u\n", config->rules.topic_count);
    for (unsigned i = 0; i < config->rules.topic_count; i++) {
        struct topic_rule *r = &config->rules.topic[i];
        mosquitto_log_printf(MOSQ_LOG_INFO, "  - %s [%s] -> %s\n", r->id, r->name, r->action);
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "=========================================\n\n");
}
