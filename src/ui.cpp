#include "../include/ui.hpp"
#include "../include/Keepass.hpp"
#include <fstream>
#include <limits>
#include <map>

std::string getFile()
{
    std::cout << "Entrez le nom de la sauvegarde ou du nouveau fichier : ";
    std::string fileName;
    std::cin >> fileName;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return fileName;
}

std::string getKey()
{
    std::cout << "Renseignez votre mot de passe : ";
    std::string key;
    std::cin >> key;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return key;
}

void ui()
{
    std::cout << "\nBienvenue dans votre gestionnaire de mot de passe\n\n";
    std::string fileName = getFile();
    std::string key = getKey();
    Keepass safeDeposit;
    StateSave state = safeDeposit.open(fileName, key);
    while (state == StateSave::Invalid)
    {
        std::cout << "Votre mot de passe est invalide" << std::endl;
        std::string fileName = getFile();
        std::string key = getKey();
        state = safeDeposit.open(fileName, key);
    }
    if (state == StateSave::Created)
    {
        std::cout << "Votre fichier sera cree une fois le programme fermer" << std::endl;
    }

    if (state == StateSave::Restored)
    {
        std::cout << "\nVotre sauvegarde a ete restaure\n\n";
    }
    std::string command, platform, username, password;
    std::map<std::string, IDEntries>::iterator it;
    while (true)
    {
        std::cout << "(a: ajouter, p: afficher, q: quitter)" << std::endl;
        std::getline(std::cin, command);
        if (command == "q")
        {
            break;
        }
        if (command == "a")
        {
            std::cout << "Entrez la plateforme : ";
            std::getline(std::cin, platform);
            std::cout << "Entrez votre nom d'utilisateur : ";
            std::getline(std::cin, username);
            std::cout << "Entrez votre mot de passe : ";
            std::getline(std::cin, password);
            if (safeDeposit.add(platform, username, password))
            {
                std::cout << "Votre compte a bien été créé" << std::endl;
            }
            std::cout << "Une Erreur c'est produite" << std::endl;
        }
        if (command == "p")
        {
            std::cout << "Entrez le nom de la plateforme : ";
            std::getline(std::cin, platform);
            it = safeDeposit.get(platform);
            std::cout << "\nPlateforme : " << it->first << std::endl;
            std::cout << "Nom utilisateur : " << it->second.username << std::endl;
            std::cout << "Mot de passe : " << it->second.password << "\n\n";
        }
    }
}