#include "../include/Keepass.hpp"
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <memory>
#include <time.h>

std::string Keepass::generatePassword()
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
    for (int i = 0; i < 10; i++)
    {
        character = letters[rand() % 68];
        password.push_back(character);
    }
    return password;
}

enum StateSave Keepass::checkKey(const std::string &key)
{
    if (key.size() > 16)
    {
        return StateSave::TooLong;
    }
    if (key.size() < 8)
    {
        return StateSave::TooShort;
    }
    // recherche de la clé dans un dictionnaire
    std::ifstream dictionary("ressource/10-million-password-list-top-100000.txt");
    // taille du fichier
    dictionary.seekg(0, dictionary.end);
    size_t dictionarySize = dictionary.tellg();
    dictionary.seekg(0, dictionary.beg);

    // Lecture
    std::unique_ptr<char[]> dictionaryKey_ptr = std::make_unique<char[]>(dictionarySize);
    dictionary.read(dictionaryKey_ptr.get(), dictionarySize);
    std::stringstream dictionaryKey;
    dictionaryKey << dictionaryKey_ptr.get();

    // Test de comparaison
    std::string word;
    while (std::getline(dictionaryKey, word))
    {
        if (key.compare(word) == 0)
        {
            return StateSave::TooEasy;
        }
    }
    return StateSave::IsGood;
}

enum StateSave Keepass::open(const std::string &fileName, const std::string &key)
{
    this->stateSave = StateSave::Error;
    this->_fileSaveName = fileName;
    this->_key = key;
    std::ifstream file(fileName, std::ios::in | std::ios::binary);
    enum StateSave stateKey = this->checkKey(key);

    // Regarde si le fichier existe pas
    if (!file.is_open())
    {
        file.close();
        if (stateKey == StateSave::IsGood)
        {
            this->stateSave = StateSave::Created;
            return StateSave::Created;
        }
        else
        {
            return stateKey;
        }
    }

    // Récupération de la taille du fichier
    file.seekg(0, file.end);
    size_t fileSize = file.tellg();
    file.seekg(0, file.beg);

    if (fileSize == 0)
    {
        file.close();
        if (stateKey == StateSave::IsGood)
        {
            this->stateSave = StateSave::Created;
            return StateSave::Created;
        }
        else
        {
            return stateKey;
        }
    }
    if (this->restore(file, fileSize))
    {
        this->stateSave = StateSave::Restored;
        return StateSave::Restored;
    }
    return StateSave::Invalid;
}

bool Keepass::restore(std::ifstream &file, const size_t fileSize)
{
    // récupération des données
    std::unique_ptr<char[]> fileContent = std::make_unique<char[]>(fileSize + 1);
    file.read(fileContent.get(), fileSize);

    //  déchiffrement des données
    std::stringstream accountData;
    try
    {
        accountData << this->aes.decrypt(fileContent.get(), this->_key);
    }
    catch (std::invalid_argument const &erreur)
    {
        file.close();
        return false;
    }

    // Restauration des données
    std::string accountEncode;
    while (std::getline(accountData, accountEncode))
    {
        AccountEntries accountDecode = this->decode(accountEncode);
        this->add(accountDecode.platform, accountDecode.ID.username, accountDecode.ID.password);
    }
    file.close();
    return true;
}

bool Keepass::add(const std::string &platform, const std::string &username, const std::string &password)
{
    enum Incorrect IntegrityEntries = checkEntry(platform, username, password);
    if (IntegrityEntries == Incorrect::All)
    {
        return false;
    }
    IDEntries userPass{username, password};
    this->safeDepositAccount[platform] = userPass;
    return true;
}

bool Keepass::exists(const std::string &platform)
{
    std::map<std::string, IDEntries>::iterator It;
    for (It = std::begin(this->safeDepositAccount); It != this->safeDepositAccount.end(); ++It)
    {
        if (platform.compare(It->first) == 0)
        {
            return true;
        }
    }
    return false;
}

bool Keepass::remove(const std::string &platform)
{
    if (this->exists(platform))
    {
        this->safeDepositAccount.erase(platform);
        return true;
    }
    return false;
}

enum Incorrect Keepass::checkEntry(const std::string &platform, const std::string &username, const std::string &password)
{
    bool checkPlatform = platform.find(sepEntries) == std::string::npos;
    bool checkUsername = username.find(sepEntries) == std::string::npos;
    bool checkPassword = password.find(sepEntries) == std::string::npos;
    if (checkPlatform && checkUsername && checkPassword)
    {
        return Incorrect::Nothing;
    }
    else
    {
        return Incorrect::All;
    }
}

std::map<std::string, IDEntries>::iterator Keepass::get(const std::string &platform)
{
    std::map<std::string, IDEntries>::iterator it;
    for (it = std::begin(this->safeDepositAccount); it != std::end(safeDepositAccount); ++it)
    {
        if (platform.compare(it->first) == 0)
        {
            return it;
        }
    }
    return it;
}

std::string Keepass::encode(std::map<std::string, IDEntries>::iterator &it)
{
    std::stringstream accountEncode;

    accountEncode << it->first << sepEntries << it->second.username << sepEntries << it->second.password << '\n';
    return accountEncode.str();
}

AccountEntries Keepass::decode(std::string accountEncode)
{
    AccountEntries entries;
    size_t usernameIndex = accountEncode.find(sepEntries) + 1;
    size_t passwordIndex = accountEncode.find(sepEntries, usernameIndex) + 1;

    entries.platform = accountEncode.substr(0, usernameIndex - 1);
    entries.ID.username = accountEncode.substr(usernameIndex, passwordIndex - usernameIndex - 1);
    entries.ID.password = accountEncode.substr(passwordIndex, accountEncode.size() - passwordIndex);
    return entries;
}

std::string Keepass::formatForSave()
{
    std::stringstream saveDeposit;
    std::map<std::string, IDEntries>::iterator it;

    // Si safeDeposit accout est vide retourner un chaîne de caractère vide
    if (it == std::end(this->safeDepositAccount))
    {
        return "";
    }
    for (it = std::begin(this->safeDepositAccount); it != std::end(this->safeDepositAccount); ++it)
    {
        saveDeposit << this->encode(it);
    }
    return saveDeposit.str();
}

Keepass::~Keepass()
{
    // Si le fichier est ni créer ou ni restaurer ne rien faire
    if (!(this->stateSave == StateSave::Created || this->stateSave == StateSave::Restored))
    {
        return;
    }
    std::string saveDeposit = this->formatForSave();

    // Si rien à sauvegarder ne rien faire
    if (saveDeposit.size() == 0 && this->stateSave == StateSave::Created)
    {
        return;
    }
    std::string dataEncrypt = this->aes.encrypt(saveDeposit, this->_key);
    std::ofstream file(this->_fileSaveName, std::ios::trunc);
    file << dataEncrypt;
    file.close();
}
