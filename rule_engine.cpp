#include "rule_engine.hpp"

rule_engine_t::clause_t::clause_t(const nlohmann::json &p_json)
{
    m_field  = p_json["field"];
    m_value = p_json["value"];
}

rule_engine_t::rule_t::rule_t(const nlohmann::json &p_json)
{
    m_allow = p_json["allow"];

    for (const auto &p_it : p_json["clauses"]) {
        m_clauses.push_back(clause_t(p_it));
    }
}

rule_engine_t::rule_engine_t(){};

rule_engine_t::~rule_engine_t(){};

void
rule_engine_t::add_rule(const nlohmann::json &p_json)
{
    std::unique_lock l_guard(m_lock);

    m_rules.push_back(rule_t(p_json));
}

const std::optional<bool>
rule_engine_t::get_verdict(
    const struct nfq_event_t       &p_nfq_event,
    const struct connection_info_t &p_info
) noexcept {
    std::shared_lock l_guard(m_lock);

    for (const auto &l_rule : m_rules) {
        bool l_match = true;

        for (const auto &l_clause : l_rule.m_clauses) {
            if (l_clause.m_field == "executable") {
                if (l_clause.m_value != p_info.m_executable) {
                    l_match = false;

                    break;
                }
            }
        }

        if (l_match) {
            return std::optional<bool>(l_rule.m_allow);
        }
    }

    return std::nullopt;
}