#ifndef __KEEPASS__
#define __KEEPASS__
#include <string>
#include <map>
#include <array>
#include <sstream>

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
    Keepass() = delete;
    Keepass(const std::string &fileSaveName);
    bool add(const std::string &account, const std::string &user, const std::string &password);
    std::map<std::string, PassEntry>::iterator get(const std::string &account);
    ~Keepass();

private:
    std::string _fileSaveName;
    enum Incorrect checkEntry(const std::string &account, const std::string &user, const std::string &password);
    std::map<std::string, PassEntry> safeDepositIdentifier;
    std::stringstream formatForSave();
};

#endif