#include "../include/test.hpp"
#include "../include/Keepass.hpp"
#include <cassert>
#include <iostream>

void test()
{
    Keepass safeDeposit;
    const std::string account = "Google";
    const std::string user = "Marc-Antoine";
    const std::string password = "Tetris123@";

    // Test d'ajout
    assert(safeDeposit.add(account, user, password) == true);
    std::map<std::string, PassEntry>::iterator it;
    it = safeDeposit.get(account);

    assert(it->first.compare(account) == 0);
    assert(it->second.user == user);
    assert(it->second.password == password);
    it = safeDeposit.get("null");

    // Test de la politique des valeurs d'entrées
    assert(!safeDeposit.add("test\\", user, password));
    assert(!safeDeposit.add(account, "test\\", password));
    assert(!safeDeposit.add(account, user, "test\\"));

    std::cout << "Test ok" << std::endl;
}