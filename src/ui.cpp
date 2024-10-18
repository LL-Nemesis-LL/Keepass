#include "../include/ui.hpp"
#include "../include/Keepass.hpp"
#include <fstream>
#include <limits>
#include <map>

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
    std::cout << "\nBienvenue dans votre gestionnaire de mot de passe\n\n";
    std::string fileName = getFile();
    std::cout << "\nSouhaite vous utilisez le generateur de mot de passe ?" << std::endl;
    std::cout << "Si oui tapez 'oui' ou tapez sur une autre touche : ";
    std::string rep;
    std::getline(std::cin, rep);
    if (rep.compare("oui") == 0)
    {
        std::cout << "Mot de passe suggérer : " << generatePassword() << std::endl;
    }
    std::string key = getKey();
    Keepass safeDeposit;
    StateSave state = safeDeposit.open(fileName, key);

    switch (state)
    {
    case StateSave::Invalid:
        while (state == StateSave::Invalid)
        {
            std::cout << "\nLe mot de passe de la sauvegarde que vous tentez d'ouvrir,\nn'est pas le bon.\n\n";
            std::string fileName = getFile();
            std::string key = getKey();
            state = safeDeposit.open(fileName, key);
        }
        break;
    case StateSave::Created:
        std::cout << "\nVotre fichier sera cree une fois le programme fermer\n\n";
        break;
    case StateSave::Restored:
        std::cout << "\nVotre sauvegarde a ete restaure\n\n";
        break;
    case StateSave::TooShort:
        std::cout << "\nVotre mot de passe est trop court (8 caracteres minimum)\n\n";
        break;
    case StateSave::TooLong:
        std::cout << "\nVotre mot de passe est trop long (16 caracteres maximum)\n\n";
        break;
    case StateSave::TooEasy:
        std::cout << "\nVotre mot de passe est trop facile\n\n";
        break;
    default:
        break;
    }
    std::string command, platform, username, password;
    std::map<std::string, IDEntries>::iterator it;
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
                std::cout << "la platform : " << platform << "existe déjà,\n";
                std::cout << "Etes-vous sur de vouloir la modifie?\n";
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
                std::cout << "Votre compte a bien ete cree" << std::endl;
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
                it = safeDeposit.get(platform);
                std::cout << "\nPlateforme : " << it->first << std::endl;
                std::cout << "Nom utilisateur : " << it->second.username << std::endl;
                std::cout << "Mot de passe : " << it->second.password << "\n\n";
            }
            else
            {
                std::cout << "\nCette plateforme n'existe pas\n\n";
            }
        }
        if (command == "R")
        {
            std::cout << "Entrez le nom de la plateforme : ";
            std::getline(std::cin, platform);
            if (safeDeposit.remove(platform))
            {
                std::cout << "\nLa plateforme " << platform << " a bien ete supprime\n\n";
            }
            else
            {
                std::cout << "\nLa plateforme " << platform << " n'extiste pas\n\n";
            }
        }
    }
}