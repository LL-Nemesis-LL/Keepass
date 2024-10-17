#include "../include/test.hpp"
#include "../include/Keepass.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <memory>

void test()
{

    std::string fileName = "test.txt";

    std::string key = "jgvhhfg12";
    std::unique_ptr<Keepass> safeDeposit = std::make_unique<Keepass>();
    StateSave state = safeDeposit->open(fileName, key);
    assert(state == StateSave::Created || state == StateSave::Restored);

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

    // Test vérification de mot de passe
    Keepass safeDepositRestauration;

    std::string fileNameCheckPassword = "test2.txt";
    std::ifstream file2(fileNameCheckPassword);
    if (file2.is_open() == 1)
    {
        std::cerr << "\nPour le bon deroulement du test,\n";
        std::cerr << "Le fichier : '" << fileNameCheckPassword << "' doit etre supprime\n\n";
        file.close();
        assert(0 == 1);
    }
    file.close();
    assert(safeDepositRestauration.open(fileNameCheckPassword, "little") == StateSave::TooShort);
    assert(safeDepositRestauration.open(fileNameCheckPassword, "password too long") == StateSave::TooLong);
    assert(safeDepositRestauration.open(fileNameCheckPassword, "qwertyuiop") == StateSave::TooEasy);

    // Test restauration et de déchirement
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