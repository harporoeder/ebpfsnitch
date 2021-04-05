#pragma once

#include <list>
#include <unordered_map>
#include <optional>

template<typename key_t, typename value_t>
class lru_map {
public:
    lru_map(const size_t p_max_size): m_max_size(p_max_size) {};

    void
    insert(const key_t &p_key, const value_t &p_value)
    {
        const auto l_iterator = m_map.find(p_key);

        if (l_iterator != m_map.end()) {
            m_list.erase(l_iterator->second);
            m_list.push_front(*l_iterator->second);
            l_iterator->second->second = p_value;
        } else {
            m_list.push_front(std::pair<key_t, value_t>{p_key, p_value});
            m_map[p_key] = m_list.begin();
        }

        if (m_map.size() > m_max_size) {
            m_map.erase(m_list.back().first);
            m_list.pop_back();
        }
    }

    std::optional<value_t>
    lookup(const key_t &p_key) const
    {
        const auto l_iterator = m_map.find(p_key);

        if (l_iterator != m_map.end()) {
            return std::optional<value_t>(l_iterator->second->second);
        } else {
            return std::nullopt;
        }
    }

private:
    const size_t m_max_size;

    std::list<std::pair<key_t, value_t>> m_list;

    std::unordered_map<
        key_t,
        typename std::list<std::pair<key_t, value_t>>::iterator
    > m_map;
};
