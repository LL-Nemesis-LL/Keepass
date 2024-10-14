#include "../include/Keepass.hpp"
#include <string>
#include <map>

void Keepass::add(const std::string &account, const std::string &user, const std::string &password)
{
    PassEntry userPass{user, password};
    this->safeDepositIdentifier[account] = userPass;
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
