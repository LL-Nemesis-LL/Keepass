#include "../include/ui.hpp"
#include "../include/Keepass.hpp"
#include <fstream>
#include <limits>
#include <map>
#include <time.h>

std::string getFile()
{
    std::cout << "Entrez le nom de la sauvegarde ou du nouveau fichier : ";
    std::string fileName;
    std::getline(std::cin, fileName);
    return fileName;
}

std::string getKey()
{
    std::cout << "Renseignez votre mot de passe : ";
    std::string key;
    std::getline(std::cin, key);
    return key;
}
bool isFileExist(const std::string &fileName)
{
    std::ifstream file(fileName);
    return file.is_open();
}

std::string generatePassword()
{
    std::array<char, 68> letters{
        35, 36, 37, 38, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
        73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
        87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105,
        106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
        118, 119, 120, 121, 122, 49, 50, 51, 52, 53, 54, 55, 56, 57};
    srand(time(NULL));
    std::string password;
    char character;
    for (int i = 0; i < 12; i++)
    {
        character = letters[rand() % 68];
        password.push_back(character);
    }
    return password;
}

void ui()
{
    std::cout << std::endl
              << "Bienvenue dans votre gestionnaire de mot de passe" << std::endl
              << std::endl;
    std::string fileName = getFile();
    if (!isFileExist(fileName))
    {
        std::cout << std::endl
                  << "Souhaite vous utilisez le générateur de mot de passe ?" << std::endl;
        std::cout << "Si oui tapez 'oui' ou tapez sur une autre touche : ";
        std::string rep;
        std::getline(std::cin, rep);
        if (rep.compare("oui") == 0)
        {
            std::cout << std::endl
                      << "Mot de passe suggéré : " << generatePassword() << std::endl
                      << std::endl;
        }
    }

    std::string key = getKey();
    Keepass safeDeposit;
    try
    {
        safeDeposit.open(fileName, key);
    }
    catch (std::invalid_argument &error)
    {
        std::cerr << error.what() << std::endl;
    }
    /*
        switch (state)
        {
        case StateSave::Invalid:
            while (state == StateSave::Invalid)
            {
                std::cout << std::endl
                          << "Le mot de passe de la sauvegarde que vous tentez d'ouvrir," << std::endl
                          << "n'est pas le bon." << std::endl
                          << std::endl;
                std::string fileName = getFile();
                std::string key = getKey();
                state = safeDeposit.open(fileName, key);
            }
            break;
        case StateSave::Created:
            std::cout << std::endl
                      << "Votre fichier sera créé une fois le programme fermer" << std::endl
                      << std::endl;
            break;
        case StateSave::Restored:
            std::cout << std::endl
                      << "Votre sauvegarde a été restauré" << std::endl
                      << std::endl;
            break;
        case StateSave::TooShort:
            std::cout << std::endl
                      << "Votre mot de passe est trop court (8 caracteres minimum)" << std::endl
                      << std::endl;
            break;
        case StateSave::TooLong:
            std::cout << std::endl
                      << "Votre mot de passe est trop long (16 caracteres maximum)" << std::endl
                      << std::endl;
            break;
        case StateSave::TooEasy:
            std::cout << std::endl
                      << "Votre mot de passe est trop facile" << std::endl
                      << std::endl;
            break;
        default:
            break;
        }
        */
    std::string command, platform, username, password;
    while (true)
    {
        std::cout << "(A: ajouter, a: afficher, q: quitter" << std::endl;
        std::cout << "R: remove)" << std::endl;
        std::getline(std::cin, command);
        if (command == "q")
        {
            break;
        }
        if (command == "A")
        {
            std::cout << "Entrez la plateforme : ";
            std::getline(std::cin, platform);
            std::cout << "Entrez votre nom d'utilisateur : ";
            std::getline(std::cin, username);
            std::cout << "Entrez votre mot de passe : ";
            std::getline(std::cin, password);
            if (safeDeposit.exists(platform))
            {
                std::cout << "la platform : " << platform << "existe déjà," << std::endl;
                std::cout << "Etês-vous sur de vouloir la modifié?" << std::endl;
                std::cout << "Sinon tapez 'non', si oui appuyer sur une touche : ";
                std::getline(std::cin, command);
                if (command == "non")
                {
                    continue;
                }
                std::cout << std::endl;
            }
            if (safeDeposit.add(platform, username, password))
            {
                std::cout << "Votre compte a bien été créé" << std::endl;
                continue;
            }
            std::cout << "Une Erreur c'est produite" << std::endl;
        }
        if (command == "a")
        {
            std::cout << "Entrez le nom de la plateforme : ";
            std::getline(std::cin, platform);
            if (safeDeposit.exists(platform))
            {
                std::map<std::string, IDEntries>::const_iterator it = safeDeposit.get(platform);
                std::cout << std::endl
                          << "Plateforme : " << it->first << std::endl;
                std::cout << "Nom utilisateur : " << it->second.username << std::endl;
                std::cout << "Mot de passe : " << it->second.password << std::endl
                          << std::endl;
            }
            else
            {
                std::cout << std::endl
                          << "Cette plateforme n'existe pas" << std::endl
                          << std::endl;
            }
        }
        if (command == "R")
        {
            std::cout << "Entrez le nom de la plateforme : ";
            std::getline(std::cin, platform);
            if (safeDeposit.remove(platform))
            {
                std::cout << std::endl
                          << "La plateforme " << platform << " a bien été supprimé" << std::endl
                          << std::endl;
            }
            else
            {
                std::cout << std::endl
                          << "La plateforme " << platform << " n'extiste pas" << std::endl
                          << std::endl;
            }
        }
    }
}