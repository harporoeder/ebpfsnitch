#include <cassert>

#include "lru_map.hpp"

static void
test_lookup_does_not_exist()
{
    const lru_map<int, int> map(1);

    assert(map.lookup(52).has_value() == false);
}

static void
test_insert_and_get()
{
    lru_map<int, int> map(1);

    map.insert(5, 10);

    assert(map.lookup(5) == std::optional<int>(10));
}

static void
test_eviction()
{
    lru_map<int, int> map(2);

    map.insert(1, 2);
    map.insert(3, 4);
    map.insert(5, 6);

    assert(map.lookup(1).has_value() == false);
    assert(map.lookup(3) == std::optional<int>(4));
    assert(map.lookup(5) == std::optional<int>(6));
}

static void
test_insert_updates_existing()
{
    lru_map<int, int> map(2);

    map.insert(1, 2);
    map.insert(3, 4);
    map.insert(1, 5);
    map.insert(6, 7);

    assert(map.lookup(3).has_value() == false);
    assert(map.lookup(1) == std::optional<int>(5));
    assert(map.lookup(6) == std::optional<int>(7));
}

int
main()
{
    test_lookup_does_not_exist();
    test_insert_and_get();
    test_eviction();
    test_insert_updates_existing();

    return 0;
}
