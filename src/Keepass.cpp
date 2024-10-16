#include "../include/Keepass.hpp"
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <memory>

enum StateSave Keepass::open(const std::string &fileName, const std::string &key)
{
    this->_fileSaveName = fileName;
    this->_key = key;
    std::ifstream file(fileName, std::ios::in | std::ios::binary);

    // Assure que le fichier est ouvert
    if (!file.is_open())
    {
        return StateSave::Created;
    }

    // Récupération de la taille du fichier
    file.seekg(0, file.end);
    size_t fileSize = file.tellg();
    file.seekg(0, file.beg);

    if (fileSize == 0)
    {
        file.close();
        return StateSave::Created;
    }
    if (this->restore(file, fileSize))
    {
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
        std::cerr << "Erreur à la restoration" << erreur.what();
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

std::stringstream Keepass::formatForSave()
{
    std::stringstream saveDeposit;
    std::map<std::string, IDEntries>::iterator it;
    for (it = std::begin(this->safeDepositAccount); it != std::end(this->safeDepositAccount); ++it)
    {
        saveDeposit << this->encode(it);
    }
    return saveDeposit;
}

Keepass::~Keepass()
{
    std::string saveDeposit = this->formatForSave().str();
    std::string dataEncrypt = this->aes.encrypt(saveDeposit, this->_key);
    std::ofstream file(this->_fileSaveName, std::ios::out | std::ios::trunc);
    file << dataEncrypt;
    file.close();
}
