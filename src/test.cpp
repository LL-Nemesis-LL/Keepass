#include "../include/test.hpp"
#include "../include/Keepass.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <memory>
#include <cstdio>

struct Pair_ErrorAndMessageError
{
    const std::string error;
    const std::string messageError;
};

void test()
{

    const std::string fileName("testKeepass.txt");
    std::unique_ptr<Keepass> safeDeposit = std::make_unique<Keepass>();

    // Test de la complexité d'un mot de passe
    const Pair_ErrorAndMessageError errorPairTooShort = {"litte", "The password is too short"};
    const Pair_ErrorAndMessageError errorPairTooLong = {"password too long", "The password is too long"};
    const Pair_ErrorAndMessageError errorPairTooEasy = {"qwertyuiop", "The password is too easy"};
    const std::array<const Pair_ErrorAndMessageError, 3> errorMessages{errorPairTooShort, errorPairTooLong, errorPairTooEasy};
    for (size_t i = 0; i < errorMessages.size(); i++)
    {
        try
        {
            safeDeposit->open(fileName, errorMessages[i].error);
        }
        catch (std::invalid_argument &error)
        {
            if (errorMessages[i].messageError.compare(error.what()) != 0)
            {
                std::cerr << "Erreur test: " << error.what() << std::endl;
                throw;
            }
        }
    }

    // Génération aléatoire d'un clé
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
    const std::string user("Marc-Antoine");
    const std::string password("Tetris123@");

    // Test d'ajout
    assert(safeDeposit->add(platform, user, password) == true);
    std::map<std::string, IDEntries>::const_iterator it = safeDeposit->get(platform);

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

    // Test restauration
    safeDeposit.reset(new Keepass());
    try
    {
        safeDeposit->open(fileName, key);
    }
    catch (std::invalid_argument &error)
    {
        std::cerr << "Erreur test, fonction open, Test restauration" << error.what() << std::endl;
        throw;
    }

    // Test validité de la restauration
    std::map<std::string, IDEntries>::const_iterator it2 = safeDeposit->get(platform);

    assert(it2->first.compare(platform) == 0);
    assert(it2->second.username.compare(user) == 0);
    assert(it2->second.password.compare(password) == 0);

    // Test de la méthode "exist"
    assert(safeDeposit->exists(platform) == true);
    assert(safeDeposit->exists("aleatoire") == false);

    // Test de la méthode "remove"
    assert(safeDeposit->remove(platform) == true);
    assert(safeDeposit->remove("aleatoire") == false);

    // Supression du fichier de test
    safeDeposit.reset();
    assert(remove(fileName.data()) == 0);

    std::cout << "Test ok" << std::endl;
}