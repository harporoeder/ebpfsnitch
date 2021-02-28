#include <unordered_map>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "rule_engine.hpp"

const std::unordered_map<std::string, field_t> g_field_map = {
    { "executable",         field_t::executable          },
    { "destinationAddress", field_t::destination_address },
    { "destinationPort",    field_t::destination_port    },
    { "containerId",        field_t::container_id        }
};

field_t
field_from_string(const std::string &p_field)
{
    const auto l_iter = g_field_map.find(p_field);

    if (l_iter != g_field_map.end()) {
        return l_iter->second;
    }

    throw std::runtime_error("invalid field");
}

rule_engine_t::clause_t::clause_t(const nlohmann::json &p_json)
{
    m_field  = field_from_string(p_json["field"]);
    m_value = p_json["value"];
}

rule_engine_t::rule_t::rule_t(
    const nlohmann::json &p_json,
    const std::string    &p_rule_id
){
    m_allow = p_json["allow"];

    for (const auto &p_it : p_json["clauses"]) {
        m_clauses.push_back(clause_t(p_it));
    }

    m_rule_id = p_rule_id;
}

rule_engine_t::rule_engine_t(){};

rule_engine_t::~rule_engine_t(){};

std::string
rule_engine_t::add_rule(const nlohmann::json &p_json)
{
    const std::string l_uuid = boost::uuids::to_string(
        boost::uuids::random_generator()()
    );

    std::unique_lock l_guard(m_lock);

    m_rules.push_back(rule_t(p_json, l_uuid));

    return l_uuid;
}

void
rule_engine_t::delete_rule(const std::string &p_rule_id) noexcept
{
    std::unique_lock l_guard(m_lock);

    m_rules.erase(
        std::remove_if(m_rules.begin(), m_rules.end(), [&](const auto &l_rule) {
            return l_rule.m_rule_id == p_rule_id;
        }),
        m_rules.end()
    );
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
            switch (l_clause.m_field) {
                case field_t::executable: {
                    if (l_clause.m_value != p_info.m_executable) {
                        l_match = false;
                    }

                    break;
                }
                case field_t::destination_address: {
                    const std::string l_addr =
                        ipv4_to_string(p_nfq_event.m_destination_address);

                    if (l_clause.m_value != l_addr) {
                        l_match = false;
                    }

                    break;
                }
                case field_t::destination_port: {
                    if (l_clause.m_value !=
                        std::to_string(p_nfq_event.m_destination_port))
                    {
                        l_match = false;
                    }

                    break;
                }
            }

            if (l_match == false) {
                break;
            }
        }

        if (l_match) {
            return std::optional<bool>(l_rule.m_allow);
        }
    }

    return std::nullopt;
}