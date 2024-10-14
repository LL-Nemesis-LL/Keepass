#include "../include/Keepass.hpp"
#include <string>
#include <map>
#include <fstream>
#include <sstream>

Keepass::Keepass(const std::string &fileSaveName) : _fileSaveName(fileSaveName)
{
}

bool Keepass::add(const std::string &account, const std::string &user, const std::string &password)
{
    enum Incorrect IntegrityEntry = checkEntry(account, user, password);
    if (IntegrityEntry == Incorrect::All)
    {
        return false;
    }
    PassEntry userPass{user, password};
    this->safeDepositIdentifier[account] = userPass;
    return true;
}

enum Incorrect Keepass::checkEntry(const std::string &account, const std::string &user, const std::string &password)
{
    bool checkAccount = account.find('\\') == std::string::npos;
    bool checkUser = user.find('\\') == std::string::npos;
    bool checkPassword = password.find('\\') == std::string::npos;
    if (checkAccount && checkUser && checkPassword)
    {
        return Incorrect::Nothing;
    }
    else
    {
        return Incorrect::All;
    }
}

std::map<std::string, PassEntry>::iterator Keepass::get(const std::string &account)
{
    std::map<std::string, PassEntry>::iterator it;
    for (it = std::begin(this->safeDepositIdentifier); it != std::end(safeDepositIdentifier); ++it)
    {
        if (account.compare(it->first) == 0)
        {
            return it;
        }
    }
    return it;
}

std::stringstream Keepass::formatForSave()
{
    std::stringstream saveDeposit;
    std::map<std::string, PassEntry>::iterator it;
    for (it = std::begin(this->safeDepositIdentifier); it != std::end(this->safeDepositIdentifier); ++it)
    {
        saveDeposit << it->first << '\\' << it->second.user << '\\' << it->second.password << '\n';
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
