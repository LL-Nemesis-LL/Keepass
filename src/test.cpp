#include "../include/test.hpp"
#include "../include/Keepass.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <memory>
#include <cstdio>
#include <array>

void test()
{

    std::string fileName = "test.txt";
    std::array<std::string, 5> errorMessages{
        "The password is too long",
        "The password is too short",
        "The file '10-million-password...' has been corrumped",
        "The file '10-million-password...' isn't opened",
        "The password is too easy"};
    std::unique_ptr<Keepass> safeDeposit = std::make_unique<Keepass>();
    const std::string key = safeDeposit->generatePassword();
    try
    {
        safeDeposit->open(fileName, key);
    }
    catch (std::exception &error)
    {
        std::cerr << error.what() << std::endl;
        return;
    }
    const std::string platform("Google");
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
    // Création de la sauvegarde
    safeDeposit.reset();

    // Test vérification de mot de passe

    std::string fileNameCheckPassword = "test2.txt";
    std::ifstream file2(fileNameCheckPassword);
    if (file2.is_open() == 1)
    {
        std::cerr << "\nPour le bon deroulement du test,\n";
        std::cerr << "Le fichier : '" << fileNameCheckPassword << "' doit etre supprime\n\n";
        file2.close();
        assert(0 == 1);
    }
    file2.close();

    std::unique_ptr<Keepass> safeDepositRestauration = std::make_unique<Keepass>();

    try
    {
        safeDepositRestauration->open(fileNameCheckPassword, "little");
    }
    catch (std::invalid_argument &error)
    {
        if (errorMessages[1].compare(error.what()) != 0)
        {
            std::cerr << "Erreur test: " << error.what() << std::endl;
            throw;
        }
    }
    try
    {
        safeDepositRestauration->open(fileNameCheckPassword, "password too long");
    }
    catch (std::invalid_argument &error)
    {
        if (errorMessages[0].compare(error.what()) != 0)
        {
            std::cerr << "Erreur test: " << error.what() << std::endl;
            throw;
        }
    }
    try
    {
        safeDepositRestauration->open(fileNameCheckPassword, "qwertyuiop");
    }
    catch (std::invalid_argument &error)
    {
        if (errorMessages[4].compare(error.what()) != 0)
        {
            std::cerr << "Erreur test: " << error.what() << std::endl;
            throw;
        }
    }

    // Test restauration et de déchirement
    try
    {
        safeDepositRestauration->open(fileName, key);
    }
    catch (std::invalid_argument &error)
    {
        std::cerr << "Erreur test, fonction open, Test restauration" << error.what() << std::endl;
        throw;
    }

    it = safeDepositRestauration->get(platform);

    assert(it->first.compare(platform) == 0);
    assert(it->second.username.compare(user) == 0);
    assert(it->second.password.compare(password) == 0);

    // Test de la méthode "exist"

    assert(safeDepositRestauration->exists(platform) == true);
    assert(safeDepositRestauration->exists("aleatoire") == false);

    // Test de la méthode "remove"
    assert(safeDepositRestauration->remove(platform) == true);
    assert(safeDepositRestauration->remove("aleatoire") == false);

    // Supression du fichier de test
    safeDepositRestauration.reset();
    assert(remove(fileName.data()) == 0);
    std::cout << "Test ok" << std::endl;
}