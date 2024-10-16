#include "../include/test.hpp"
#include "../include/Keepass.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <memory>

void test()
{
    std::string fileName = "test.txt";
    std::string key = "test";
    std::unique_ptr<Keepass> safeDeposit = std::make_unique<Keepass>();
    assert(safeDeposit->open(fileName, key) == StateSave::Created);

    const std::string platform = "Google";
    const std::string user = "Marc-Antoine";
    const std::string password = "Tetris123@";

    // Test d'ajout
    assert(safeDeposit->add(platform, user, password) == true);
    std::map<std::string, IDEntries>::iterator it;
    it = safeDeposit->get(platform);

    assert(it->first.compare(platform) == 0);
    assert(it->second.username.compare(user) == 0);
    assert(it->second.password.compare(password) == 0);

    // Test de la politique des valeurs d'entrées
    std::string badEntry("test");
    badEntry.push_back(sepEntries);
    assert(!safeDeposit->add(badEntry, user, password));
    assert(!safeDeposit->add(platform, badEntry, password));
    assert(!safeDeposit->add(platform, user, badEntry));
    // Test sauvegarde des données
    assert(safeDeposit->add("Facebook", "Bylal", "byby123") == true);
    safeDeposit.reset();
    std::ifstream file(fileName, std::ios::in);
    assert(file.is_open());

    file.seekg(0, file.end);
    size_t fileSize = file.tellg();
    file.seekg(0, file.beg);
    assert(fileSize == 64);

    std::string content;
    std::getline(file, content);

    // Test restauration et de déchirement
    Keepass safeDepositRestauration;
    assert(safeDepositRestauration.open(fileName, key) == StateSave::Restored);

    it = safeDepositRestauration.get(platform);

    assert(it->first.compare(platform) == 0);
    assert(it->second.username.compare(user) == 0);
    assert(it->second.password.compare(password) == 0);

    // Test de la méthode "exist"

    assert(safeDepositRestauration.exists(platform) == true);
    assert(safeDepositRestauration.exists("aleatoire") == false);

    // Test de la méthode "remove"
    assert(safeDepositRestauration.remove("Facebook") == true);
    assert(safeDepositRestauration.remove("aleatoire") == false);

    std::cout << "Test ok" << std::endl;
}