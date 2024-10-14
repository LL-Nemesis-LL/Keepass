#ifndef __KEEPASS__
#define __KEEPASS__
#include <string>
#include <map>
#include <array>

struct PassEntry
{
    std::string user;
    std::string password;
};
class Keepass
{

public:
    void add(const std::string &account, const std::string &user, const std::string &password);
    std::map<std::string, PassEntry>::iterator get(const std::string &account);

private:
    std::map<std::string, PassEntry> safeDepositIdentifier;
};

#endif