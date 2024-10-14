#ifndef __KEEPASS__
#define __KEEPASS__
#include <string>
#include <map>
#include <array>

enum class Incorrect
{
    Nothing,
    Account,
    User,
    Password,
    AccountUser,
    UserPassword,
    PasswordAccout,
    All
};

struct PassEntry
{
    std::string user;
    std::string password;
};
class Keepass
{

public:
    bool add(const std::string &account, const std::string &user, const std::string &password);
    std::map<std::string, PassEntry>::iterator get(const std::string &account);

private:
    enum Incorrect checkEntry(const std::string &account, const std::string &user, const std::string &password);
    std::map<std::string, PassEntry> safeDepositIdentifier;
};

#endif