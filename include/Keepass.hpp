#ifndef __KEEPASS__
#define __KEEPASS__
#include <string>
#include <map>
#include <array>
#include <sstream>
#include "AES.hpp"

const char sepEntries = '\\';

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
    IDEntries ID;
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
    std::string _key = "test";
    enum Incorrect checkEntry(const std::string &platform, const std::string &username, const std::string &password);
    std::map<std::string, IDEntries> safeDepositAccount;
    std::string encode(std::map<std::string, IDEntries>::iterator &it);
    AccountEntries decode(std::string content);
    EasyAES aes;
    std::stringstream formatForSave();
};

#endif