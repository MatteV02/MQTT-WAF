/**
 * @file waf_rules_parse.h
 * @brief WAF rules parsing data structures and function prototypes.
 *
 * @defgroup waf_rules_parse Rules Parser
 * @brief WAF rules parsing data structures and function prototypes.
 * @ingroup rules
 *
 * @{
 */

#ifndef WAF_RULES_PARSE_H_
#define WAF_RULES_PARSE_H_

#include <stdbool.h>
#include <regex.h>

/* ---------------------------------------------------------
 * WAF DATA STRUCTURES
 * --------------------------------------------------------- */

/**
 * @brief Defines the default fallback policies for the WAF.
 */
struct default_policies {
    char *publish;          /**< Default action for publish events */
    char *subscribe;        /**< Default action for subscribe events */
};

/**
 * @brief Defines a rule for inspecting and filtering MQTT messages.
 */
struct message_rule {
    char *id;                       /**< Unique identifier for the rule */
    char *name;                     /**< Human-readable name of the rule */
    char *action;                   /**< Action to take (e.g., "allow", "deny", or "drop") */
    char **topics;                  /**< Array of topics this rule applies to */
    unsigned topics_count;          /**< Number of topics in the topics array */
    char *payload_regex;            /**< Raw regular expression string for matching the payload */
    regex_t compiled_payload_regex; /**< Compiled regex object for the payload */
    bool has_payload_regex;         /**< Flag indicating if the payload regex was successfully compiled */
    bool log;                       /**< Flag indicating if matches should be logged */
    bool invert_match;              /**< Flag indicating if the logic should be inverted (trigger on mismatch) */
};

/**
 * @brief Defines publish and subscribe permissions for a topic rule.
 */
struct topic_permissions {
    char **publish;          /**< Array of topics allowed/denied for publishing */
    unsigned publish_count;  /**< Number of topics in the publish array */
    char **subscribe;        /**< Array of topics allowed/denied for subscribing */
    unsigned subscribe_count;/**< Number of topics in the subscribe array */
};

/**
 * @brief Defines a rule governing topic access for specific clients.
 */
struct topic_rule {
    char *id;                         /**< Unique identifier for the rule */
    char *name;                       /**< Human-readable name of the rule */
    char *action;                     /**< Action to take (e.g., "allow" or "deny") */
    char *client_id_regex;            /**< Raw regular expression string for matching client IDs */
    regex_t compiled_client_id_regex; /**< Compiled regex object for client ID matching */
    bool has_client_id_regex;         /**< Flag indicating if the client ID regex was successfully compiled */
    struct topic_permissions permissions; /**< Publishing and subscribing permissions */
};

/**
 * @brief Wrapper containing all rule categories separated into arrays.
 */
struct rules_section {
    struct message_rule *message;               /**< Array of message rules */
    unsigned message_count;                     /**< Number of message rules */
    struct topic_rule *topic;                   /**< Array of topic rules */
    unsigned topic_count;                       /**< Number of topic rules */
};

/**
 * @brief Top-level Configuration Node representing the entire loaded YAML structure.
 */
struct waf_config {
    char *version;                           /**< WAF rules file version */
    struct default_policies default_policies;/**< Global fallback policies */
    struct rules_section rules;              /**< Parsed rules grouped by category */
};

/* ---------------------------------------------------------
 * FUNCTION PROTOTYPES
 * --------------------------------------------------------- */

/**
 * @brief Loads the WAF YAML rules file into dynamically allocated C arrays.
 * * Parses the provided YAML file using libcyaml, applies default values for 
 * missing fields, and compiles any provided regular expressions.
 * * @param filepath Path to the YAML rule definitions file.
 * @return Struct pointer containing separate rule arrays, or NULL on failure.
 */
struct waf_config* load_waf_rules(const char *filepath);

/**
 * @brief Cleanly frees all memory allocations generated during the parsing process.
 * * Safely releases memory allocated by libcyaml and frees compiled regex structures.
 * Call this inside mosquitto_plugin_cleanup.
 * * @param config Pointer to the loaded waf_config struct to be freed.
 */
void free_waf_rules(struct waf_config *config);

/**
 * @brief Prints a formatted summary of the loaded WAF rules to standard output.
 * * Useful for debugging and verifying that the YAML structure was correctly 
 * parsed and mapped to the internal C structs.
 * * @param config Pointer to the loaded waf_config struct.
 */
void print_waf_rules(struct waf_config *config);

#endif /* WAF_RULES_PARSE_H_ */

/** @} */