#include "../include/test.hpp"
#include "../include/Keepass.hpp"
#include <cassert>
#include <iostream>
#include <fstream>

void test()
{

    std::string fileName = "test.txt";
    Keepass safeDeposit(fileName);
    const std::string account = "Google";
    const std::string user = "Marc-Antoine";
    const std::string password = "Tetris123@";

    // Test d'ajout
    assert(safeDeposit.add(account, user, password) == true);
    std::map<std::string, IDEntries>::iterator it;
    it = safeDeposit.get(account);

    assert(it->first.compare(account) == 0);
    assert(it->second.username.compare(user) == 0);
    assert(it->second.password.compare(password) == 0);

    // Test de la politique des valeurs d'entrées
    std::string badEntry("test");
    badEntry.push_back(sepEntries);
    assert(!safeDeposit.add(badEntry, user, password));
    assert(!safeDeposit.add(account, badEntry, password));
    assert(!safeDeposit.add(account, user, badEntry));
    // Test sauvegarde des données
    assert(safeDeposit.add("Facebook", "Bylal", "byby123") == true);
    safeDeposit.~Keepass();
    std::ifstream file(fileName, std::ios::in);
    assert(file.is_open());

    file.seekg(0, file.end);
    size_t fileSize = file.tellg();
    file.seekg(0, file.beg);
    assert(fileSize == 68);

    std::string content;
    std::getline(file, content);

    // Test restauration et de déchirement
    Keepass safeDepositRestauration(fileName);

    it = safeDepositRestauration.get(account);

    assert(it->first.compare(account) == 0);
    assert(it->second.username.compare(user) == 0);
    assert(it->second.password.compare(password) == 0);

    std::cout << "Test ok" << std::endl;
}