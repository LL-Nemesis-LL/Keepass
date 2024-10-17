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
enum class StateSave
{
    Restored,
    Created,
    Invalid,
    Error,
    TooShort,
    TooLong,
    TooEasy,
    IsGood
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
    enum StateSave checkKey(const std::string &key);
    enum StateSave open(const std::string &fileName, const std::string &key);
    bool add(const std::string &platform, const std::string &username, const std::string &password);
    std::map<std::string, IDEntries>::iterator get(const std::string &plateform);
    bool exists(const std::string &platform);
    bool remove(const std::string &platforme);
    ~Keepass();

private:
    std::string _fileSaveName;
    std::string _key;
    StateSave stateSave = StateSave::Error;
    bool restore(std::ifstream &file, const size_t fileSize);
    enum Incorrect checkEntry(const std::string &platform, const std::string &username, const std::string &password);
    std::map<std::string, IDEntries> safeDepositAccount;
    std::string encode(std::map<std::string, IDEntries>::iterator &it);
    AccountEntries decode(std::string content);
    EasyAES aes;
    std::string formatForSave();
};

#endif