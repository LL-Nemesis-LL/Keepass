#include "../include/Keepass.hpp"
#include <string>
#include <map>
#include <fstream>
#include <sstream>

Keepass::Keepass(const std::string &fileSaveName) : _fileSaveName(fileSaveName)
{
    std::ifstream file(this->_fileSaveName, std::ios::in);
    if (!file.is_open())
    {
        return;
    }
    int i = 0;
    std::cout << "Debut de la restauration\n\n";
    while (!file.eof())
    {
        std::string accountEncrypt;
        std::getline(file, accountEncrypt);
        if (accountEncrypt.size() == 0)
        {
            break;
        }
        i++;
        std::string accountEncode = this->aes.decrypt(accountEncrypt, this->_key);

        AccountEntries accountDecode = this->decode(accountEncode);

        this->add(accountDecode.platform, accountDecode.ID.username, accountDecode.ID.password);
    }
    std::cout << "fin de la restauration\n\n";
    file.close();
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

    accountEncode << it->first << sepEntries << it->second.username << sepEntries << it->second.password;
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
        saveDeposit << this->aes.encrypt(this->encode(it), this->_key) << '\n';
    }
    return saveDeposit;
}

Keepass::~Keepass()
{
    std::string saveDeposit = this->formatForSave().str();
    std::ofstream file(this->_fileSaveName, std::ios::out | std::ios::trunc);
    file << saveDeposit;
    file.close();
}
