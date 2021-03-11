#pragma once

#include <vector>
#include <shared_mutex>

#include <nlohmann/json.hpp>

#include "misc.hpp"

enum class field_t {
    executable,
    destination_address,
    destination_port,
    source_address,
    source_port,
    container_id,
    protocol,
    user_id
};

field_t field_from_string(const std::string &p_field);

std::string field_to_string(const field_t p_field);

class rule_engine_t {
public:
    rule_engine_t();

    ~rule_engine_t();

    std::string add_rule(const nlohmann::json &p_json);

    const std::optional<bool>
    get_verdict(
        const struct nfq_event_t       &p_nfq_event,
        const struct connection_info_t &p_info
    ) noexcept;

    void delete_rule(const std::string &p_rule_id) noexcept;

    const nlohmann::json rules_to_json(const bool p_filter_temporary=false);

private:
    struct clause_t {
        clause_t(const nlohmann::json &p_json);

        field_t      m_field;
        std::string m_value;
    };

    struct rule_t {
        rule_t(const nlohmann::json &p_json, const std::string &p_rule_id);

        std::vector<struct clause_t> m_clauses;
        std::string                  m_rule_id;
        bool                         m_allow;
        uint32_t                     m_priority;
        bool                         m_persistent;
    };

    static nlohmann::json clause_to_json(const clause_t &p_clause);
    static nlohmann::json rule_to_json(const rule_t &p_rule);

    std::shared_mutex m_lock;

    std::vector<struct rule_t> m_rules;

    void save_rules();
    void try_load_rules();
};