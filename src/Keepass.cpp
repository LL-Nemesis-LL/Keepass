#include "../include/Keepass.hpp"
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <memory>
#include <time.h>
#include <openssl/evp.h>

std::string Keepass::generatePassword()
{
    std::array<char, 68> letters{
        35, 36, 37, 38, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
        73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
        87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105,
        106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
        118, 119, 120, 121, 122, 49, 50, 51, 52, 53, 54, 55, 56, 57};
    srand(time(NULL));
    std::string password;
    char character;
    for (int i = 0; i < __maxSizePassword; i++)
    {
        character = letters[rand() % 68];
        password.push_back(character);
    }
    return password;
}
char *sha256File(std::string &fileNameDictionary)
{
    std::ifstream fichier(fileNameDictionary, std::ios::binary);
    constexpr int lenBlock = 255;
    fichier.seekg(0, fichier.end);
    size_t lenFichier = fichier.tellg();
    fichier.seekg(0, fichier.beg);
    int nbrBlock = lenFichier / lenBlock;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    const int lenSha256 = EVP_MD_get_size(sha256);
    EVP_DigestInit_ex(ctx, sha256, NULL);

    unsigned char block[lenBlock];
    for (int i = 0; i < nbrBlock; i++)
    {
        fichier.read(reinterpret_cast<char *>(block), lenBlock);
        EVP_DigestUpdate(ctx, block, lenBlock);
    }
    int lenLastData = lenFichier % lenBlock;
    unsigned char lastBlock[lenLastData];
    if (lenLastData != 0)
    {
        fichier.read(reinterpret_cast<char *>(lastBlock), lenLastData);
        EVP_DigestUpdate(ctx, lastBlock, lenLastData);
    }
    fichier.close();

    std::unique_ptr<unsigned char[]> outdigest = std::make_unique<unsigned char[]>(lenSha256);
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, outdigest.get(), &len);
    char *hash = new char[sizeof(char) * ((lenSha256 * 2) + 1)];
    for (int i = 0; i < lenSha256; i++)
    {
        sprintf(&hash[i * 2], "%02x", outdigest[i]);
    }
    hash[lenSha256 * 2] = '\0';
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(sha256);

    return hash;
}

void Keepass::checkKey(const std::string &key)
{
    if (key.size() > __maxSizePassword)
    {
        throw std::invalid_argument("The password is too long");
    }
    if (key.size() < 8)
    {
        throw std::invalid_argument("The password is too short");
    }
    // recherche de la clé dans un dictionnaire
    std::string fileDictonaryName("ressource/10-million-password-list-top-100000.txt");
    std::unique_ptr<char[]> hash(sha256File(fileDictonaryName));
    std::string hashGot(hash.get());
    constexpr char hashExcepted[] = "b0d9a2015610d68c80602a5fdd1212561e2844a9bb013db5a2bda81a5ff30ffd\0";
    if (hashGot.compare(hashExcepted) != 0)
    {
        throw std::invalid_argument("The file '10-million-password...' has been corrumped");
    }
    std::ifstream dictionary(fileDictonaryName);
    if (!dictionary.is_open())
    {
        throw std::invalid_argument("The file '10-million-password...' isn't opened");
    }
    // taille du fichier
    dictionary.seekg(0, dictionary.end);
    size_t dictionarySize = dictionary.tellg();
    dictionary.seekg(0, dictionary.beg);

    // Lecture
    std::unique_ptr<char[]> dictionaryKey_ptr = std::make_unique<char[]>(dictionarySize + 1);
    dictionary.read(dictionaryKey_ptr.get(), dictionarySize);
    std::stringstream dictionaryKey;
    dictionaryKey << dictionaryKey_ptr.get();

    // Test de comparaison
    std::string word;
    while (std::getline(dictionaryKey, word))
    {
        if (key.compare(word) == 0)
        {
            throw std::invalid_argument("The password is too easy");
        }
    }
    return;
}

void Keepass::open(const std::string &fileName, const std::string &key)
{
    // Check if the key respect the policy
    this->_key = key;
    this->checkKey(key);

    this->stateSave = StateSave::Error;
    this->_fileSaveName = fileName;

    std::ifstream file(fileName, std::ios::binary);

    // Regarde si le fichier existe pas
    if (!file.is_open())
    {
        file.close();
        this->stateSave = StateSave::Created;
        return;
    }

    // Récupération de la taille du fichier
    file.seekg(0, file.end);
    size_t fileSize = file.tellg();
    file.seekg(0, file.beg);

    if (fileSize == 0)
    {
        file.close();
        this->stateSave = StateSave::Created;
        return;
    }
    else
    {
        this->restore(file, fileSize);
    }
}

bool Keepass::restore(std::ifstream &file, const size_t fileSize)
{
    // récupération des données
    std::unique_ptr<char[]> fileContent = std::make_unique<char[]>(fileSize + 1);
    file.read(fileContent.get(), fileSize);
    file.close();

    //  déchiffrement des données
    std::stringstream accountData;
    try
    {
        accountData << this->aes.decrypt(std::move(fileContent), fileSize, this->_key);
    }
    catch (std::invalid_argument const &erreur)
    {
        return false;
    }
    this->stateSave = StateSave::Restored;

    // Restauration des données
    std::string accountEncode;
    while (std::getline(accountData, accountEncode))
    {
        AccountEntries accountDecode = this->decode(accountEncode);
        this->add(accountDecode.platform, accountDecode.ID.username, accountDecode.ID.password);
    }
    return true;
}

bool Keepass::add(const std::string &platform, const std::string &username, const std::string &password)
{
    if (!(this->stateSave == StateSave::Created || this->stateSave == StateSave::Restored))
    {
        throw std::invalid_argument("Méthode Keepass::add : Le fichier de restauration n'a pas été initialisé");
    }
    enum Incorrect IntegrityEntries = checkEntry(platform, username, password);
    if (IntegrityEntries == Incorrect::All)
    {
        return false;
    }
    IDEntries userPass{username, password};
    this->safeDepositAccount[platform] = userPass;
    return true;
}

bool Keepass::exists(const std::string &platform) const
{
    std::map<std::string, IDEntries>::const_iterator It;
    for (It = std::begin(this->safeDepositAccount); It != this->safeDepositAccount.end(); ++It)
    {
        if (platform.compare(It->first) == 0)
        {
            return true;
        }
    }
    return false;
}

bool Keepass::remove(const std::string &platform)
{
    if (this->exists(platform))
    {
        this->safeDepositAccount.erase(platform);
        return true;
    }
    return false;
}

enum Incorrect Keepass::checkEntry(const std::string &platform, const std::string &username, const std::string &password) const
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

std::map<std::string, IDEntries>::const_iterator Keepass::get(const std::string &platform) const
{
    std::map<std::string, IDEntries>::const_iterator it;
    for (it = std::begin(this->safeDepositAccount); it != std::end(safeDepositAccount); ++it)
    {
        if (platform.compare(it->first) == 0)
        {
            return it;
        }
    }
    return it;
}

std::string Keepass::encode(const std::map<std::string, IDEntries>::const_iterator &it) const
{
    std::stringstream accountEncode;

    accountEncode << it->first << sepEntries << it->second.username << sepEntries << it->second.password << std::endl;
    return accountEncode.str();
}

AccountEntries Keepass::decode(const std::string accountEncode) const
{
    AccountEntries entries;
    size_t usernameIndex = accountEncode.find(sepEntries) + 1;
    size_t passwordIndex = accountEncode.find(sepEntries, usernameIndex) + 1;

    entries.platform = accountEncode.substr(0, usernameIndex - 1);
    entries.ID.username = accountEncode.substr(usernameIndex, passwordIndex - usernameIndex - 1);
    entries.ID.password = accountEncode.substr(passwordIndex, accountEncode.size() - passwordIndex);
    return entries;
}

std::string Keepass::formatForSave()
{
    // Si safeDeposit accout est vide retourner un chaîne de caractère vide
    if (std::begin(this->safeDepositAccount) == std::end(this->safeDepositAccount))
    {
        return "";
    }

    std::stringstream saveDeposit;
    std::map<std::string, IDEntries>::iterator it;
    for (it = std::begin(this->safeDepositAccount); it != std::end(this->safeDepositAccount); ++it)
    {
        saveDeposit << this->encode(it);
    }
    return saveDeposit.str();
}

Keepass::~Keepass()
{
    // Si le fichier est ni créer ou ni restaurer ne rien faire
    if (!(this->stateSave == StateSave::Created || this->stateSave == StateSave::Restored))
    {
        return;
    }
    std::string saveDeposit = this->formatForSave();

    // Si rien à sauvegarder ne rien faire
    if (saveDeposit.size() == 0 && this->stateSave == StateSave::Created)
    {
        return;
    }
    std::string dataEncrypt = this->aes.encrypt(saveDeposit, this->_key);
    std::ofstream file(this->_fileSaveName, std::ios::trunc | std::ios::binary);
    file << dataEncrypt;
    file.close();
}
