#ifndef __KEEPASS__
#define __KEEPASS__
#include <string>
#include <map>
#include <array>
#include <sstream>
#include "AES.hpp"

static constexpr char sepEntries = '\\';
static constexpr int __maxSizePassword{16};

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
    std::string generatePassword();
    void open(const std::string &fileName, const std::string &key);
    bool add(const std::string &platform, const std::string &username, const std::string &password);
    std::map<std::string, IDEntries>::const_iterator get(const std::string &plateform) const;
    bool exists(const std::string &platform) const;
    bool remove(const std::string &platforme);
    ~Keepass();

private:
    std::string _fileSaveName;
    std::string _key;
    StateSave stateSave = StateSave::Error;
    void checkKey(const std::string &key);
    bool restore(std::ifstream &file, const size_t fileSize);
    enum Incorrect checkEntry(const std::string &platform, const std::string &username, const std::string &password) const;
    std::map<std::string, IDEntries> safeDepositAccount;
    std::string encode(const std::map<std::string, IDEntries>::const_iterator &it) const;
    AccountEntries decode(const std::string content) const;
    EasyAES aes;
    std::string formatForSave();
};

#endif