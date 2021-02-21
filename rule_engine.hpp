#pragma once

#include <vector>
#include <shared_mutex>

#include <nlohmann/json.hpp>

#include "structs.h"

class rule_engine_t {
public:
    rule_engine_t();

    ~rule_engine_t();

    void add_rule(const nlohmann::json &p_json);

    const std::optional<bool>
    get_verdict(
        const struct nfq_event_t       &p_nfq_event,
        const struct connection_info_t &p_info
    ) noexcept;

private:
    struct clause_t {
        clause_t(const nlohmann::json &p_json);

        std::string m_field;
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