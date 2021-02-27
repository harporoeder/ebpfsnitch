#pragma once

#include <vector>
#include <shared_mutex>

#include <nlohmann/json.hpp>

#include "misc.hpp"

enum class field_t {
    executable,
    destination_address,
    destination_port,
    container_id
};

field_t field_from_string(const std::string &p_field);

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

private:
    struct clause_t {
        clause_t(const nlohmann::json &p_json);

        field_t      m_field;
        std::string m_value;
    };

    struct rule_t {
        rule_t(const nlohmann::json &p_json);

        std::vector<struct clause_t> m_clauses;

        bool m_allow;
    };

    std::shared_mutex m_lock;

    std::vector<struct rule_t> m_rules;
};