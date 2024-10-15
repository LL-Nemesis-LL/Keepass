#ifndef __KEEPASS__
#define __KEEPASS__
#include <string>
#include <map>
#include <array>
#include <sstream>

enum class Incorrect
{
    Nothing,
    Plateform,
    User,
    Password,
    PlateformUser,
    UserPassword,
    PasswordAccout,
    All
};

struct IDEntries
{
    std::string username;
    std::string password;
};
struct AccountEntries
{
    std::string platform;
    std::string username;
    std::string password;
};
class Keepass
{

public:
    Keepass() = delete;
    Keepass(const std::string &fileSaveName);
    bool add(const std::string &platform, const std::string &username, const std::string &password);
    std::map<std::string, IDEntries>::iterator get(const std::string &plateform);
    ~Keepass();

private:
    std::string _fileSaveName;
    enum Incorrect checkEntry(const std::string &platform, const std::string &username, const std::string &password);
    std::map<std::string, IDEntries> safeDepositAccount;
    std::string encode(std::map<std::string, IDEntries>::iterator &it);
    AccountEntries decode(std::string content);
    std::stringstream formatForSave();
};

#endif