#include "commands.h"
#include "exceptions.h"
#include "git-version.h"
#include "lite_operations.h"
#include "lock_enabled.h"
#include "myutils.h"
#include "operations.h"
#include "platform.h"
#include "win_get_proc.h"

#include <argon2.h>
#include <cryptopp/cpu.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/secblock.h>
#include <fuse.h>
#include <json/json.h>
#include <tclap/CmdLine.h>
#include <utf8proc/utf8proc.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

using namespace securefs;

namespace
{

const char* const CONFIG_FILE_NAME = ".securefs.json";
const unsigned MIN_ITERATIONS = 20000;
const unsigned MIN_DERIVE_SECONDS = 1;
// size_t（size_type）可以提高代码的可移植性、有效性、可读性，表示取值范围是目标平台下最大的可能范围。不同位数的os上定义不一样，但都为无符号整数。
const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;

const char* const PBKDF_ALGO_PKCS5 = "pkcs5-pbkdf2-hmac-sha256";
const char* const PBKDF_ALGO_SCRYPT = "scrypt";
const char* const PBKDF_ALGO_ARGON2ID = "argon2id";

const char* const EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED = " ";

const char* get_version_header(unsigned version)
{
    switch (version)
    {
    case 1:
    case 2:
    case 3:
        return "version=1";    // These headers are all the same for backwards compatible behavior
                               // with old mistakes
    case 4:
        return "version=4";
    default:
        throwInvalidArgumentException("Unknown format version");
    }
}

// 创建json读取对象（详细文档看库手册）
std::unique_ptr<Json::CharReader> create_json_reader()
{
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true;
    return std::unique_ptr<Json::CharReader>(builder.newCharReader());
}

enum class NLinkFixPhase
{
    CollectingNLink,
    FixingNLink
};

// TODO:修复硬链接计数，待细看
void fix_hardlink_count(operations::FileSystemContext* fs,
                        Directory* dir,
                        std::unordered_map<id_type, int, id_hash>* nlink_map,
                        NLinkFixPhase phase)
{
    std::vector<std::pair<id_type, int>> listings;
    {
        FileLockGuard file_lock_guard(*dir);
        dir->iterate_over_entries(
            [&listings](const std::string&, const id_type& id, int type)
            {
                listings.emplace_back(id, type);
                return true;
            });
    }

    for (auto&& entry : listings)
    {
        id_type& id = std::get<0>(entry);
        int type = std::get<1>(entry);

        AutoClosedFileBase base(nullptr, nullptr);
        try
        {
            base = open_as(fs->table, id, FileBase::BASE);
        }
        catch (...)
        {
            continue;
        }
        switch (phase)
        {
        case NLinkFixPhase::FixingNLink:
        {
            auto& fp = *base;
            FileLockGuard file_lock_guard(fp);
            fp.set_nlink(nlink_map->at(id));
        }
        break;

        case NLinkFixPhase::CollectingNLink:
            nlink_map->operator[](id)++;
            break;

        default:
            UNREACHABLE();
        }
        base.reset(nullptr);
        if (type == FileBase::DIRECTORY)
        {
            fix_hardlink_count(
                fs, open_as(fs->table, id, type).get_as<Directory>(), nlink_map, phase);
        }
    }
}

// 对所有entry的type进行修复
void fix_helper(operations::FileSystemContext* fs,
                Directory* dir,
                const std::string& dir_name,
                std::unordered_set<id_type, id_hash>* all_ids)
{
    std::vector<std::tuple<std::string, id_type, int>> listings;
    {
        FileLockGuard file_lock_guard(*dir);
        dir->iterate_over_entries(
            [&listings](const std::string& name, const id_type& id, int type)
            {
                listings.emplace_back(name, id, type);
                return true;
            });
    }

    for (auto&& entry : listings)
    {
        const std::string& name = std::get<0>(entry);
        id_type& id = std::get<1>(entry);
        int type = std::get<2>(entry);

        AutoClosedFileBase base(nullptr, nullptr);
        try
        {
            base = open_as(fs->table, id, FileBase::BASE);
        }
        catch (const std::exception& e)
        {
            fprintf(stderr,
                    "Encounter exception when opening %s: %s\nDo you want to remove the entry? "
                    "(Yes/No, default: no)\n",
                    (dir_name + '/' + name).c_str(),
                    e.what());
            auto remove = [&]()
            {
                FileLockGuard file_lock_guard(*dir);
                dir->remove_entry(name, id, type);
            };
            auto ignore = []() {};
            respond_to_user_action({{"\n", ignore},
                                    {"y\n", remove},
                                    {"yes\n", remove},
                                    {"n\n", ignore},
                                    {"no\n", ignore}});
            continue;
        }

        int real_type = base->get_real_type();
        if (type != real_type)
        {
            printf("Mismatch type for %s (inode has type %s, directory entry has type %s). Do you "
                   "want to fix it? (Yes/No default: yes)\n",
                   (dir_name + '/' + name).c_str(),
                   FileBase::type_name(real_type),
                   FileBase::type_name(type));
            fflush(stdout);

            auto fix_type = [&]()
            {
                FileLockGuard file_lock_guard(*dir);
                dir->remove_entry(name, id, type);
                dir->add_entry(name, id, real_type);
            };

            auto ignore = []() {};

            respond_to_user_action({{"\n", fix_type},
                                    {"y\n", fix_type},
                                    {"yes\n", fix_type},
                                    {"n\n", ignore},
                                    {"no\n", ignore}});
        }
        all_ids->insert(id);
        base.reset(nullptr);

        if (real_type == FileBase::DIRECTORY)
        {
            fix_helper(fs,
                       open_as(fs->table, id, FileBase::DIRECTORY).get_as<Directory>(),
                       dir_name + '/' + name,
                       all_ids);
        }
    }
}

// 修复securefs文件系统
// 原理：
void fix(const std::string& basedir, operations::FileSystemContext* fs)
{
    // all_ids存放所有的id
    // unordered_set是Key类型唯一对象集合的关联容器，key为id，value为id的后几个字节
    std::unordered_set<id_type, id_hash> all_ids{fs->root_id};
    // 获得根目录AutoClosedFileBase对象
    AutoClosedFileBase root_dir = open_as(fs->table, fs->root_id, FileBase::DIRECTORY);
    // 对所有entry的type进行修复
    fix_helper(fs, root_dir.get_as<Directory>(), "", &all_ids);
    // 获得所有的id并对没有引用的id进行可选操作
    auto all_underlying_ids = find_all_ids(basedir);
    for (const id_type& id : all_underlying_ids)
    {
        if (all_ids.find(id) == all_ids.end())
        {
            printf("%s is not referenced anywhere in the filesystem, do you want to recover it? "
                   "([r]ecover/[d]elete/[i]gnore default: recover)\n",
                   hexify(id).c_str());
            fflush(stdout);

            auto recover = [&]()
            {
                auto base = open_as(fs->table, id, FileBase::BASE);
                auto& root_dir_fp = *root_dir;
                FileLockGuard file_lock_guard(root_dir_fp);
                root_dir_fp.cast_as<Directory>()->add_entry(hexify(id), id, base->get_real_type());
            };

            auto remove = [&]()
            {
                FileBase* base = fs->table.open_as(id, FileBase::BASE);
                int real_type = base->get_real_type();
                fs->table.close(base);
                auto real_file_handle = open_as(fs->table, id, real_type);
                auto& fp = *real_file_handle;
                FileLockGuard file_lock_guard(fp);
                fp.unlink();
            };

            auto ignore = []() {};

            respond_to_user_action({{"\n", recover},
                                    {"r\n", recover},
                                    {"recover\n", recover},
                                    {"i\n", ignore},
                                    {"ignore\n", ignore},
                                    {"d\n", remove},
                                    {"delete\n", remove}});
        }
    }

    // 修复硬链接（inode）问题?
    std::unordered_map<id_type, int, id_hash> nlink_map;
    puts("Fixing hardlink count ...");
    fix_hardlink_count(
        fs, root_dir.get_as<Directory>(), &nlink_map, NLinkFixPhase::CollectingNLink);
    fix_hardlink_count(fs, root_dir.get_as<Directory>(), &nlink_map, NLinkFixPhase::FixingNLink);
    puts("Fix complete");
}


void hmac_sha256(const securefs::key_type& base_key,
                 StringRef maybe_key_file_path,
                 securefs::key_type& out_key)
{
    // 如果没有用keyfile文件，则salt_effective = salt
    if (maybe_key_file_path.empty())
    {
        out_key = base_key;
        return;
    }
    // 如果用了keyfile文件，会利用keyfile文件里面的信息和hmac-sha256算法来生成salt_effective
    auto file_stream = OSService::get_default().open_file_stream(maybe_key_file_path, O_RDONLY, 0);
    byte buffer[4096];
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(base_key.data(), base_key.size());
    while (true)
    {
        auto sz = file_stream->sequential_read(buffer, sizeof(buffer));
        if (sz <= 0)
        {
            break;
        }
        hmac.Update(buffer, sz);
    }
    hmac.TruncatedFinal(out_key.data(), out_key.size());
}

// 产生配置信息函数，返回JSON格式的数据
Json::Value generate_config(unsigned int version,
                            const std::string& pbkdf_algorithm,
                            const CryptoPP::AlignedSecByteBlock& master_key,
                            StringRef maybe_key_file_path,
                            const securefs::key_type& salt,
                            const void* password,
                            size_t pass_len,
                            unsigned block_size,
                            unsigned iv_size,
                            unsigned max_padding,
                            unsigned rounds)
{
    securefs::key_type effective_salt;
    hmac_sha256(salt, maybe_key_file_path, effective_salt);

    Json::Value config;
    config["version"] = version;
    key_type password_derived_key;
    // master_key在写配置文件前就已经生成好了
    // 下面利用password经过argon2获得password_derived_key
    // 备注：e_key经过password_derived_key可以解密获得master_key，master_key的作用是加密解密文件数据？？
    CryptoPP::AlignedSecByteBlock encrypted_master_key(nullptr, master_key.size());

    if (pbkdf_algorithm == PBKDF_ALGO_PKCS5)
    {
        config["iterations"] = pbkdf_hmac_sha256(password,
                                                 pass_len,
                                                 effective_salt.data(),
                                                 effective_salt.size(),
                                                 rounds ? rounds : MIN_ITERATIONS,
                                                 rounds ? 0 : MIN_DERIVE_SECONDS,
                                                 password_derived_key.data(),
                                                 password_derived_key.size());
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_SCRYPT)
    {
        uint32_t n = rounds > 0 ? rounds : (1u << 18u), r = 8, p = 1;
        config["iterations"] = n;
        config["scrypt_r"] = r;
        config["scrypt_p"] = p;
        CryptoPP::Scrypt scrypt;
        scrypt.DeriveKey(password_derived_key.data(),
                         password_derived_key.size(),
                         static_cast<const byte*>(password),
                         pass_len,
                         effective_salt.data(),
                         effective_salt.size(),
                         n,
                         r,
                         p);
    }
    // 默认使用的是这个pbkdf_algorithm
    else if (pbkdf_algorithm == PBKDF_ALGO_ARGON2ID)
    {
        // 从环境变量中获取SECUREFS_ARGON2_M_COST的值（test中会在环境变量中设置这些值）
        const char* env_m_cost = getenv("SECUREFS_ARGON2_M_COST");
        const char* env_p = getenv("SECUREFS_ARGON2_P");
        // 环境变量中没有获取到就用代码设置
        uint32_t t_cost = rounds > 0 ? rounds : 9,
                 m_cost = env_m_cost ? std::stoi(env_m_cost) : (1u << 18u),
                 p = env_p ? std::stoi(env_p) : 4;
        config["iterations"] = t_cost;
        config["argon2_m_cost"] = m_cost;
        config["argon2_p"] = p;
        int rc = argon2id_hash_raw(t_cost,
                                   m_cost,
                                   p,
                                   password,
                                   pass_len,
                                   effective_salt.data(),
                                   effective_salt.size(),
                                   password_derived_key.data(),
                                   password_derived_key.size());
        if (rc)
        {
            throw_runtime_error("Argon2 hashing failed with status code " + std::to_string(rc));
        }
    }
    else
    {
        throw_runtime_error("Unknown pbkdf algorithm " + pbkdf_algorithm);
    }
    // 把上面的pbkdf和salt信息放到配置文件json中
    config["pbkdf"] = pbkdf_algorithm;
    config["salt"] = hexify(salt);

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    // 随机生成下面用到的iv
    generate_random(iv, array_length(iv));

    // 利用password_derived_key来加密master_key获得e_key，得到用户看得见的.securefs.json里的数据
    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(
        password_derived_key.data(), password_derived_key.size(), iv, array_length(iv));
    encryptor.EncryptAndAuthenticate(encrypted_master_key.data(),
                                     mac,
                                     array_length(mac),
                                     iv,
                                     array_length(iv),
                                     reinterpret_cast<const byte*>(get_version_header(version)),
                                     strlen(get_version_header(version)),
                                     master_key.data(),
                                     master_key.size());

    // 把上面的IV、MAC、e_key放到配置文件json中
    Json::Value encrypted_key;
    encrypted_key["IV"] = hexify(iv, array_length(iv));
    encrypted_key["MAC"] = hexify(mac, array_length(mac));
    encrypted_key["key"] = hexify(encrypted_master_key);

    config["encrypted_key"] = std::move(encrypted_key);

    // 如果format_version!=1，则block_size和iv_size是可变的，放到json中
    if (version >= 2)
    {
        config["block_size"] = block_size;
        config["iv_size"] = iv_size;
    }
    // 如果开启了padding功能，需要将max_padding信息也放到json中
    if (max_padding > 0)
    {
        config["max_padding"] = max_padding;
    }
    return config;
}

void compute_password_derived_key(const Json::Value& config,
                                  const void* password,
                                  size_t pass_len,
                                  key_type& salt,
                                  key_type& password_derived_key)
{
    unsigned iterations = config["iterations"].asUInt();
    std::string pbkdf_algorithm = config.get("pbkdf", PBKDF_ALGO_PKCS5).asString();
    VERBOSE_LOG("Setting the password key derivation function to %s", pbkdf_algorithm.c_str());

    if (pbkdf_algorithm == PBKDF_ALGO_PKCS5)
    {
        pbkdf_hmac_sha256(password,
                          pass_len,
                          salt.data(),
                          salt.size(),
                          iterations,
                          0,
                          password_derived_key.data(),
                          password_derived_key.size());
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_SCRYPT)
    {
        auto r = config["scrypt_r"].asUInt();
        auto p = config["scrypt_p"].asUInt();
        CryptoPP::Scrypt scrypt;
        scrypt.DeriveKey(password_derived_key.data(),
                         password_derived_key.size(),
                         static_cast<const byte*>(password),
                         pass_len,
                         salt.data(),
                         salt.size(),
                         iterations,
                         r,
                         p);
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_ARGON2ID)
    {
        auto m_cost = config["argon2_m_cost"].asUInt();
        auto p = config["argon2_p"].asUInt();
        int rc = argon2id_hash_raw(iterations,
                                   m_cost,
                                   p,
                                   password,
                                   pass_len,
                                   salt.data(),
                                   salt.size(),
                                   password_derived_key.data(),
                                   password_derived_key.size());
        if (rc)
        {
            throw_runtime_error("Argon2 hashing failed with status code " + std::to_string(rc));
        }
    }
    else
    {
        throw_runtime_error("Unknown pbkdf algorithm " + pbkdf_algorithm);
    }
}

// 根据配置信息来验证密码是否正确（password通过Argon2推导出AES的对称密钥），获取解密数据用的master_key
bool parse_config(const Json::Value& config,
                  StringRef maybe_key_file_path,
                  const void* password,
                  size_t pass_len,
                  CryptoPP::AlignedSecByteBlock& master_key,
                  unsigned& block_size,
                  unsigned& iv_size,
                  unsigned& max_padding)
{
    using namespace securefs;
    unsigned version = config["version"].asUInt();
    max_padding = config.get("max_padding", 0u).asUInt();

    // 根据version来获取block_size、iv_size这两个参数
    if (version == 1)
    {
        block_size = 4096;
        iv_size = 32;
    }
    else if (version == 2 || version == 3 || version == 4)
    {
        block_size = config["block_size"].asUInt();
        iv_size = config["iv_size"].asUInt();
    }
    else
    {
        throwInvalidArgumentException(strprintf("Unsupported version %u", version));
    }

    // 获取到配置文件中的encrypted_key
    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    key_type salt;
    CryptoPP::AlignedSecByteBlock encrypted_key;

    std::string salt_hex = config["salt"].asString();
    const auto& encrypted_key_json_value = config["encrypted_key"];
    std::string iv_hex = encrypted_key_json_value["IV"].asString();
    std::string mac_hex = encrypted_key_json_value["MAC"].asString();
    std::string ekey_hex = encrypted_key_json_value["key"].asString();

    // 将字符表示的16进制 转换为 对应数字表示的16进制，存在byte(无符号char)里
    parse_hex(salt_hex, salt.data(), salt.size());
    parse_hex(iv_hex, iv, array_length(iv));
    parse_hex(mac_hex, mac, array_length(mac));

    // 调整CryptoPP::AlignedSecByteBlock的size，因为1个byte=2个16进制数，所以字节数为16进制数的一半
    encrypted_key.resize(ekey_hex.size() / 2);
    parse_hex(ekey_hex, encrypted_key.data(), encrypted_key.size());
    master_key.resize(encrypted_key.size());

    // 解密验证匿名函数
    auto decrypt_and_verify = [&](const securefs::key_type& wrapping_key)
    {
        // 定义一个解密器
        CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(wrapping_key.data(), wrapping_key.size(), iv, array_length(iv));
        // 利用解密器进行解密和验证，返回bool类型
        return decryptor.DecryptAndVerify(
            // 来自函数参数，为result.master_key，存放解密后的master_key
            master_key.data(),
            mac,
            array_length(mac),
            iv,
            array_length(iv),
            reinterpret_cast<const byte*>(get_version_header(version)),
            strlen(get_version_header(version)),
            // 配置文件.securefs.json中存放的加密数据
            encrypted_key.data(),
            encrypted_key.size());
    };

    // 程序使用的是这种keyfile使用方法
    // 利用password或keyfile来得到derived_key，从而进行解密和验证，成功则返回true
    // 解密数据放在函数参数master_key中
    {
        // 利用key_file获取new_salt
        securefs::key_type new_salt;
        hmac_sha256(salt, maybe_key_file_path, new_salt);

        securefs::key_type password_derived_key;
        compute_password_derived_key(config, password, pass_len, new_salt, password_derived_key);
        if (decrypt_and_verify(password_derived_key))
        {
            return true;
        }
    }

    // TODO:程序使用的不是这种keyfile使用方法，为什么还要进行这种尝试？
    // 如果上面解密验证失败，尝试另一种使用keyfile的方法，对衍生密钥使用keyfile
    // `securefs` used to derive keyfile based key in another way. Try it here for compatibility.
    {
        securefs::key_type wrapping_key;
        securefs::key_type password_derived_key;
        compute_password_derived_key(config, password, pass_len, salt, password_derived_key);
        // 利用key_file获取new_password_derived_key
        hmac_sha256(password_derived_key, maybe_key_file_path, wrapping_key);
        return decrypt_and_verify(wrapping_key);
    }
}
}    // namespace

namespace securefs
{

// 打开配置文件函数，返回文件流
std::shared_ptr<FileStream> CommandBase::open_config_stream(const std::string& path, int flags)
{
    return OSService::get_default().open_file_stream(path, flags, 0644);
}

// 读取配置文件并解析将配置信息放到FSConfig结构体，并返回该结构及
// 输入密码后才进行这一步
// 密码正确，才能读取到配置文件，得到解密数据用的master_key等数据
// void*可以指向任意地址
FSConfig CommandBase::read_config(FileStream* stream,
                                  const void* password,
                                  size_t pass_len,
                                  StringRef maybe_key_file_path)
{
    // 配置文件对应的结构体
    FSConfig result;
    
    // 读取配置文件到一个JSON数据结构中
    std::vector<char> str;
    // 预留4000的vector大小，预留足够的大小，省得没有连续空间移来移去，这种写法能节省开销（空间换时间）
    str.reserve(4000);
    // 将内容读取成char类型的vector
    while (true)
    {
        char buffer[4000];
        auto sz = stream->sequential_read(buffer, sizeof(buffer));
        if (sz <= 0)
            break;
        str.insert(str.end(), buffer, buffer + sz);
    }
    // 通过json读取对象对内容进行解析
    Json::Value value;
    std::string error_message;
    // vector中过得data()函数返回一个指向内存数组的直接指针
    if (!create_json_reader()->parse(str.data(), str.data() + str.size(), &value, &error_message))
        throw_runtime_error(
            strprintf("Failure to parse the config file: %s", error_message.c_str()));

    // 根据配置文件对password和keyfile进行验证，验证失败会终止运行
    if (!parse_config(value,
                      maybe_key_file_path,
                      password,
                      pass_len,
                      result.master_key,
                      result.block_size,
                      result.iv_size,
                      result.max_padding))
        throw_runtime_error("Invalid password and/or keyfile");
    result.version = value["version"].asUInt();
    return result;
}

static void copy_key(const CryptoPP::AlignedSecByteBlock& in_key, key_type* out_key)
{
    if (in_key.size() != out_key->size())
        throw_runtime_error("Invalid key size");
    memcpy(out_key->data(), in_key.data(), out_key->size());
}

static void copy_key(const CryptoPP::AlignedSecByteBlock& in_key, optional<key_type>* out_key)
{
    out_key->emplace();
    copy_key(in_key, &(out_key->value()));
}

// 写入配置文件到配置文件流中（create和changepassword命令会用到这个函数）
// maybe_key_file_path传入的是std::string，会隐式转换为自己写的StringRef
void CommandBase::write_config(FileStream* stream,
                               StringRef maybe_key_file_path,
                               const std::string& pbdkf_algorithm,
                               const FSConfig& config,
                               const void* password,
                               size_t pass_len,
                               unsigned rounds)
{
    // 产生随机的salt，salt是用来Argon2推导密钥用的，这里产生的salt会存在配置文件中
    // salt在后面经过hmac-sha256后生成effective_salt，再输入到pbkdf_algorithm中
    key_type salt;
    // generate_random()利用CryptoPP实现
    generate_random(salt.data(), salt.size());
    // 产生配置文件 toStyledString()：json->string
    auto str = generate_config(config.version,
                               pbdkf_algorithm,
                               config.master_key,
                               maybe_key_file_path,
                               salt,
                               password,
                               pass_len,
                               config.block_size,
                               config.iv_size,
                               config.max_padding,
                               rounds)
                   .toStyledString();
    // stream为传入的config_stream.get()，实际为UnixFileStream指针或WindowsFileStream指针
    // 用到了多态，调用的sequential_write()为UnixFileStream或WindowsFileStream类中实现的方法
    stream->sequential_write(str.data(), str.size());
}

// A base class for all commands that require a data dir to be present.
// 需要数据目录参数命令的基类，继承CommandBase类
class _DataDirCommandBase : public CommandBase
{
protected:
    // 数据目录参数，仅输入值，不需要flag
    // MountCommand类继承了这个类，所以MountCommand类能直接用data_dir这个类成员
    TCLAP::UnlabeledValueArg<std::string> data_dir{
        "dir", "Directory where the data are stored", true, "", "data_dir"};
    // 配置文件.securefs.json存放的完全路径参数
    // 输入参数，后面需要跟值
    TCLAP::ValueArg<std::string> config_path{
        "",
        "config",
        "Full path name of the config file. ${data_dir}/.securefs.json by default",
        false,
        "",
        "config_path"};

protected:
    // 返回配置文件的完全路径
    std::string get_real_config_path()
    {
        return config_path.isSet() ? config_path.getValue()
                                   : data_dir.getValue() + PATH_SEPARATOR_CHAR + CONFIG_FILE_NAME;
    }
};

// 密码命令基类，继承自_DataDirCommandBase类
class _SinglePasswordCommandBase : public _DataDirCommandBase
{
protected:
    TCLAP::ValueArg<std::string> pass{
        "",
        "pass",
        "Password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "password"};
    TCLAP::ValueArg<std::string> keyfile{
        "",
        "keyfile",
        "An optional path to a key file to use in addition to or in place of password",
        false,
        "",
        "path"};
    TCLAP::SwitchArg askpass{
        "",
        "askpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        false};
    CryptoPP::AlignedSecByteBlock password;

    // 读取密码函数（用户输入）
    // require_confirmation表示是否需要二次验证（验证两次输入的密码是否一致）
    void get_password(bool require_confirmation)
    {
        // 如果在命令中设置了pass参数且不为空，则将其放入到password这个CryptoPP::AlignedSecByteBlock中，以便后面用cryptopp进行处理
        if (pass.isSet() && !pass.getValue().empty())
        {
            // 将命令行输入的pass存到password这个secblock中
            // reinterpret_cast<const byte*>(xx)将xx强制转换为const char*类型
            password.Assign(reinterpret_cast<const byte*>(pass.getValue().data()),
                            pass.getValue().size());
            // SecureWipeBuffer将pass字符数组擦除置0，因为它后面不用了，所以需要擦除置0，防止从内存中获取密码，这样比较安全
            CryptoPP::SecureWipeBuffer(reinterpret_cast<byte*>(&pass.getValue()[0]),
                                       pass.getValue().size());
            // 退出函数
            return;
        }
        // 当设置了keyfile 且 keyfile不为空的时候 且 没有开启askpass的时候
        // keyfile是进入系统的密钥文件路径，用于代替密码（创建系统的时候指定密钥文件，后面进去也只能用这个密钥文件）
        if (keyfile.isSet() && !keyfile.getValue().empty() && !askpass.getValue())
        {
            // 用keyfile了，把password置“ ”，此时不验证password仅验证keyfile
            password.Assign(reinterpret_cast<const byte*>(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED),
                            strlen(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED));
            return;
        }
        // 若require_confirmation为true，则需要输入两次密码，验证两次输入是否一致（用在create时）
        if (require_confirmation)
        {
            // 执行输入两次密码的函数，结果放到password中
            return OSService::read_password_with_confirmation("Enter password:", &password);
        }
        // 若require_confirmation为false，则输入一次密码
        // 执行输入一次密码的函数，结果放到password中
        return OSService::read_password_no_confirmation("Enter password:", &password);
    }

    // 添加来自基类（singlepassword及其子类）的待解析参数
    void add_all_args_from_base(TCLAP::CmdLine& cmd_line)
    {
        cmd_line.add(&data_dir);
        cmd_line.add(&config_path);
        cmd_line.add(&pass);
        cmd_line.add(&keyfile);
        cmd_line.add(&askpass);
    }
};

static const std::string message_for_setting_pbkdf
    = strprintf("The algorithm to stretch passwords. Use %s for maximum protection (default), or "
                "%s for compatibility with old versions of securefs",
                PBKDF_ALGO_ARGON2ID,
                PBKDF_ALGO_PKCS5);

// create命令类，继承_SinglePasswordCommandBase类
class CreateCommand : public _SinglePasswordCommandBase
{
private:
    // rounds表示多少进行多少轮密钥推到，默认是0；随后在不同的pbkdf算法中会进行判断，若为0则会赋新值，argon2id是9
    TCLAP::ValueArg<unsigned> rounds{
        "r",
        "rounds",
        "Specify how many rounds of key derivation are applied (0 for automatic)",
        false,
        0,
        "integer"};
    // format表示securefs文件系统的格式版本
    TCLAP::ValueArg<unsigned int> format{
        "", "format", "The filesystem format version (1,2,3,4)", false, 4, "integer"};
    // IV size的作用是加密block用到的iv sieze。默认为12；但是format为1的时候iv_size不可以设置，强制设为32
    TCLAP::ValueArg<unsigned int> iv_size{
        "", "iv-size", "The IV size (ignored for fs format 1)", false, 12, "integer"};
    // block_size的作用是file对应每个block有效内容的大小。默认为4096；但是format为1的时候block_size不可以设置，强制设为4096
    TCLAP::ValueArg<unsigned int> block_size{
        "", "block-size", "Block size for files (ignored for fs format 1)", false, 4096, "integer"};
    // store_time表示是否存储和加密时间戳，format=3时默认开启了这个功能
    // 设置了store_time的话会强制把format设为3
    TCLAP::SwitchArg store_time{
        "",
        "store_time",
        "alias for \"--format 3\", enables the extension where timestamp are stored and encrypted"};
    // pbkdf表示使用何种pbkdf算法，默认是argon2id
    TCLAP::ValueArg<std::string> pbkdf{
        "", "pbkdf", message_for_setting_pbkdf, false, PBKDF_ALGO_ARGON2ID, "string"};
    // max-padding表示填充到所有文件的最大数量，每个block进行随机填充，作用是混淆文件的大小，开启这个功能会产生巨大的性能消耗
    TCLAP::ValueArg<unsigned> max_padding{
        "",
        "max-padding",
        "Maximum number of padding to add to all files in order to obfuscate their sizes. Each "
        "file has a different padding. Enabling this has a large performance cost.",
        false,
        0,
        "int"};

public:
    // 解析命令函数
    void parse_cmdline(int argc, const char* const* argv) override
    {
        // 创建tclap::cmdline对象，help_message()用于描述命令用途输出
        TCLAP::CmdLine cmdline(help_message());
        // 添加来自基类（singlepassword及其子类）的待解析参数
        add_all_args_from_base(cmdline);
        // 添加当前类需要待解析的参数
        cmdline.add(&iv_size);
        cmdline.add(&rounds);
        cmdline.add(&format);
        cmdline.add(&store_time);
        cmdline.add(&block_size);
        cmdline.add(&pbkdf);
        cmdline.add(&max_padding);
        // 进行解析
        cmdline.parse(argc, argv);
        // 读取密码（用户输入），存到password这个类属性中了，因为是创建系统所以需要二次确认，故require_confirmation=true
        get_password(true);
    }

    // create命令执行主函数
    int execute() override
    {
        // format和store_time同时设置了会报错并结束程序
        // 即format和store_time不能同时设置，store_time在format3时会默认开启，并且设置store_time会把format强制设置为3
        if (format.isSet() && store_time.isSet())
        {
            fprintf(stderr, "Conflicting flags --format and --store_time are specified together\n");
            return 1;
        }

        // 当format=1的时候，不可以设置iv_size和block_size，设置了会报错并结束程序
        if (format.isSet() && format.getValue() == 1 && (iv_size.isSet() || block_size.isSet()))
        {
            fprintf(stderr,
                    "IV and block size options are not available for filesystem format 1\n");
            return 1;
        }

        // 获取format_version，设置了store_time的话强制把format设为3，否则就是format
        unsigned format_version = store_time.isSet() ? 3 : format.getValue();

        // 创建data_dir文件夹，Tip：get_default()这个函数的写法很强
        OSService::get_default().ensure_directory(data_dir.getValue(), 0755);

        // 创建配置文件的结构体（master_key等数据）注意.securefs.json中存放的是master_key加密后的密文
        FSConfig config;
        // 调整类型为CryptoPP::AlignedSecByteBlock的config.master_key的大小，format=4时为4*32字节，format<4时为32字节
        // 每个CryptoPP::AlignedSecByteBlock类型变量中data以byte字节为单位
        config.master_key.resize(format_version < 4 ? KEY_LENGTH : 4 * KEY_LENGTH);
        // 使用CryptoPP::OS_GenerateRandomBlock函数，随机生成master_key
        CryptoPP::OS_GenerateRandomBlock(false, config.master_key.data(), config.master_key.size());

        // 给配置文件结构体的一些变量赋值
        config.iv_size = format_version == 1 ? 32 : iv_size.getValue();
        config.version = format_version;
        config.block_size = block_size.getValue();
        config.max_padding = max_padding.getValue();

        // config_stream为打开.securefs.json的配置文件流，是一个FileStream类型的shared_ptr
        // get_real_config_path()返回配置文件的完全路径or相对路径
        auto config_stream
            = open_config_stream(get_real_config_path(), O_WRONLY | O_CREAT | O_EXCL);
        // DEFER()宏的作用是将里面的代码延迟到作用域结束时执行
        // 该作用域结束时，如果存在一个未捕获或未完全处理完毕的异常，则将这个配置文件删掉
        DEFER(if (std::uncaught_exception()) {
            OSService::get_default().remove_file(get_real_config_path());
        });
        // 写入配置信息到配置文件流中（写入的是经过加密后的配置信息）
        write_config(config_stream.get(),
                     keyfile.getValue(),
                     pbkdf.getValue(),
                     config,
                     password.data(),
                     password.size(),
                     rounds.getValue());
        // 将config_stream这个shared_ptr指向释放掉，之后的引用计数应该为0，释放对象占用内存
        config_stream.reset();

        // 如果format<4，初始化文件系统，创建数据根目录的密文文件（这样挂载的时候才能找到数据根目录下的文件信息）
        if (format_version < 4)
        {
            // 定义一个挂载选项，并对相关属性赋值
            operations::MountOptions opt;
            opt.version = format_version;
            // opt.root为指向OSService对象的shared_ptr（调用带数据路径的构造函数，可以获得data_dir路径的文件描述符）
            opt.root = std::make_shared<OSService>(data_dir.getValue());
            opt.master_key = config.master_key;
            // 当format=3时，flags加入StoreTime记号，否则为0
            opt.flags = format_version < 3 ? 0 : kOptionStoreTime;
            opt.block_size = config.block_size;
            opt.iv_size = config.iv_size;

            // 创建FileSystemContext对象并进行根目录的构造，这里的构造lock_stream并没有赋值，在mount的时候才创建并赋值给lock_stream
            operations::FileSystemContext fs(opt);
            // DIRECTORY为FileBase定义的byte类型，用来表示type
            // table为ShardedFileTableImpl
            // root_id在构造的时候，初始化全为0
            // root为FileBase类的多态，里面存放了数据文件流、元数据文件流
            // root不是智能指针，但有一个智能指针存在m_files中
            auto root = fs.table.create_as(fs.root_id, FileBase::DIRECTORY);
            // root_fp为root的引用
            auto& root_fp = *root;
            // FileLockGuard与LockGuard略有不同：LockGuard实现对多个不同类上锁和flock文件锁，而FileLockGuard专门用于FileBase及其子类
            FileLockGuard file_lock_guard(root_fp);
            // 设置uid，存在m_flags[1]中，通过调用OSService::getuid()来获取调用程序的用户id
            root_fp.set_uid(securefs::OSService::getuid());
            // 设置gid，存在m_flags[2]中，通过调用OSService::getgid()来获取调用程序的组id
            root_fp.set_gid(securefs::OSService::getgid());
            // 设置mode，存在m_flags[0]中，mode表示文件类型和访问权限
            root_fp.set_mode(S_IFDIR | 0755);
            // 设置nlink，存在m_flags[3]中，nlink表示什么？？
            root_fp.set_nlink(1);
            // 刷新数据，待调试了解？？
            root_fp.flush();
        }
        return 0;
    }

    const char* long_name() const noexcept override { return "create"; }

    char short_name() const noexcept override { return 'c'; }

    const char* help_message() const noexcept override { return "Create a new filesystem"; }
};

// changepassword命令类，继承_DataDirCommandBase类
class ChangePasswordCommand : public _DataDirCommandBase
{
private:
    // 创建存放旧密码和新密码的CryptoPP::AlignedSecByteBlock变量
    CryptoPP::AlignedSecByteBlock old_password, new_password;
    // rounds表示多少进行多少轮密钥推到，默认是0；随后在不同的pbkdf算法中会进行判断，若为0则会赋新值，argon2id是9
    TCLAP::ValueArg<unsigned> rounds{
        "r",
        "rounds",
        "Specify how many rounds of key derivation are applied (0 for automatic)",
        false,
        0,
        "integer"};
    // pbkdf表示使用何种pbkdf算法，默认是argon2id
    TCLAP::ValueArg<std::string> pbkdf{
        "", "pbkdf", message_for_setting_pbkdf, false, PBKDF_ALGO_ARGON2ID, "string"};
    // 旧的keyfile路径
    TCLAP::ValueArg<std::string> old_key_file{
        "", "oldkeyfile", "Path to original key file", false, "", "path"};
    // 新的keyfile路径
    TCLAP::ValueArg<std::string> new_key_file{
        "", "newkeyfile", "Path to new key file", false, "", "path"};
    // 当开启这个功能的时候，既会验证password也会验证keyfile，默认是验证keyfile了就不会验证password
    TCLAP::SwitchArg askoldpass{
        "",
        "askoldpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        false};
    // 当开启这个功能的时候，既会验证password也会验证keyfile
    TCLAP::SwitchArg asknewpass{
        "",
        "asknewpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        false};
    // 将old_password跟在命令后面，建议是手工输比这样更安全
    TCLAP::ValueArg<std::string> oldpass{
        "",
        "oldpass",
        "The old password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "string"};
    // 将new_password跟在命令后面，建议是手工输比这样更安全
    TCLAP::ValueArg<std::string> newpass{
        "",
        "newpass",
        "The new password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "string"};

    // 将value放到output中，注意类型
    static void assign(StringRef value, CryptoPP::AlignedSecByteBlock& output)
    {
        output.Assign(reinterpret_cast<const byte*>(value.data()), value.size());
    }

public:
    // 解析命令函数
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&data_dir);
        cmdline.add(&rounds);
        cmdline.add(&config_path);
        cmdline.add(&old_key_file);
        cmdline.add(&new_key_file);
        cmdline.add(&askoldpass);
        cmdline.add(&asknewpass);
        cmdline.add(&oldpass);
        cmdline.add(&newpass);
        cmdline.add(&pbkdf);
        cmdline.parse(argc, argv);
        // 如果命令中设置了oldpass，则将其值放到old_password中
        if (oldpass.isSet())
        {
            assign(oldpass.getValue(), old_password);
        }
        // 如果原来没有用keyfile或开启了askoldpass，则需要输入旧密码
        else if (old_key_file.getValue().empty() || askoldpass.getValue())
        {
            OSService::read_password_no_confirmation("Old password: ", &old_password);
        }
        // 当原来用了keyfile，密码是“ ”时，把“ ”放到oldpassword中
        else
        {
            assign(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED, old_password);
        }
        
        // 如果命令中设置了newpass，则将其值放到new_password中
        if (newpass.isSet())
        {
            assign(newpass.getValue(), new_password);
        }
        // 如果没有设置新的keyfile或开启了asknewpass，则需要输入新密码
        else if (new_key_file.getValue().empty() || asknewpass.getValue())
        {
            OSService::read_password_with_confirmation("New password: ", &new_password);
        }
        // 当设置了新keyfile时，密码是“ ”时，把“ ”放到oldpassword中
        else
        {
            assign(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED, new_password);
        }
    }

    // changepassword命令执行主函数
    int execute() override
    {
        // 配件文件.securefs.json的源完全路径
        auto original_path = get_real_config_path();
        // 随机产生16个字节的数据
        byte buffer[16];
        generate_random(buffer, array_length(buffer));
        // 配件文件.securefs.json的暂时完全路径
        auto tmp_path = original_path + hexify(buffer, array_length(buffer));
        // 配件文件.securefs.json的源完全路径流
        auto stream = OSService::get_default().open_file_stream(original_path, O_RDONLY, 0644);
        // 读取配置信息到config结构体中
        auto config = read_config(
            stream.get(), old_password.data(), old_password.size(), old_key_file.getValue());
        // 配件文件.securefs.json的暂时完全路径流
        // 细节：stream这个shared_ptr改变指向后，原来那个对象减少一个count计数，减到0会自动释放内存
        stream = OSService::get_default().open_file_stream(
            tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        // 如果捕获到异常，删除.securefs.json的暂时路径
        DEFER(if (std::uncaught_exception()) {
            OSService::get_default().remove_file_nothrow(tmp_path);
        });
        // 根据new_password来重新写配置文件
        write_config(stream.get(),
                     new_key_file.getValue(),
                     pbkdf.getValue(),
                     config,
                     new_password.data(),
                     new_password.size(),
                     rounds.getValue());
        // 释放配件文件.securefs.json的源暂时路径流，是一个shared_ptr
        stream.reset();
        // 将tmp_path重命名为original_path
        OSService::get_default().rename(tmp_path, original_path);
        return 0;
    }

    const char* long_name() const noexcept override { return "chpass"; }

    char short_name() const noexcept override { return 0; }

    const char* help_message() const noexcept override
    {
        return "Change password/keyfile of existing filesystem";
    }
};

// 挂载命令类，继承自_SinglePasswordCommandBase类，所以MountCommand这个类能用_SinglePasswordCommandBase类中的一些属性和方法
// 利用了tclap库来实现，tclap库可以更简单的实现命令行指令的解析
class MountCommand : public _SinglePasswordCommandBase
{
private:
    // SwitchArg为开关类，如果在命令行上输入了开关对应的参数，那么getValue方法将返回与开关默认值相反的值。
    // classname x{..,..,}也能创建对象，调用对应的构造函数
    // 单线程模式，利用fuse来实现（fuse的单线程模式，即用单线程读取用户挂载点发出的系统调用请求，这样效率低、慢，但是不存在线程安全问题）
    TCLAP::SwitchArg single_threaded{"s", "single", "Single threaded mode"};
    // 在后台运行securefs，通过fuse来实现
    TCLAP::SwitchArg background{
        "b", "background", "Run securefs in the background (currently no effect on Windows)"};
    // TODO:关闭完整性验证（不安全），完整性是指什么完整？？
    // 没有加入到parse中，这个参数等于没用
    TCLAP::SwitchArg insecure{
        "i", "insecure", "Disable all integrity verification (insecure mode)"};
    // 禁用xattr功能，macos要禁用，有bug
    TCLAP::SwitchArg noxattr{"x", "noxattr", "Disable built-in xattr support"};
    // 输出更详细的log信息，调整logger等级
    TCLAP::SwitchArg verbose{"v", "verbose", "Logs more verbose messages"};
    // 跟踪所有的调用log，调整logger等级
    TCLAP::SwitchArg trace{"", "trace", "Trace all calls into `securefs` (implies --verbose)"};
    // ValueArg为解析值类，在flag后面跟上模版对应的类型的值，会解析到对应的值
    // log为日志文件的存放路径，开启后日志会保存在该文件中，不在控制台输出
    TCLAP::ValueArg<std::string> log{
        "", "log", "Path of the log file (may contain sensitive information)", false, "", "path"};
    // MultiArg与ValueArg类似，但是返回的不是一个值而是数组
    // fuse_options为附加的fuse mount操作，仅用于测试，容易使文件系统崩溃
    // 使用 ./程序 挂载点 --help 可以查看
    TCLAP::MultiArg<std::string> fuse_options{
        "o",
        "opt",
        "Additional FUSE options; this may crash the filesystem; use only for testing!",
        false,
        "options"};
    // UnlabeledValueArg类的作用是没有flag，直接在命令上输入值
    // mount_point为挂载点
    TCLAP::UnlabeledValueArg<std::string> mount_point{
        "mount_point", "Mount point", true, "", "mount_point"};
    // fsname表示挂载的时候展示的文件系统名，通过fuse实现
    TCLAP::ValueArg<std::string> fsname{
        "", "fsname", "Filesystem name shown when mounted", false, "securefs", "fsname"};
    // fssubtype表示挂载的时候文件系统子类型，通过fuse实现
    TCLAP::ValueArg<std::string> fssubtype{
        "", "fssubtype", "Filesystem subtype shown when mounted", false, "securefs", "fssubtype"};
    // 是否禁用文件锁定功能，即禁用format1-3的flock锁
    TCLAP::SwitchArg noflock{"",
                             "noflock",
                             "Disables the usage of file locking. Needed on some network "
                             "filesystems. May cause data loss, so use it at your own risk!",
                             false};
    // 文件名规范化模式，合法值:none, casefold, nfc, casefold+nfc，在mac上默认是nfc，其他平台默认none                               
    TCLAP::ValueArg<std::string> normalization{"",
                                               "normalization",
                                               "Mode of filename normalization. Valid values: "
                                               "none, casefold, nfc, casefold+nfc. Defaults to nfc "
                                               "on macOS and none on other platforms",
                                               false,
#ifdef __APPLE__
                                               "nfc",
#else
                                               "none",
#endif
                                               ""};
    // 缓存文件属性等操作的的时间，默认是30s，超过应该是超时，通过fuse实现
    TCLAP::ValueArg<int> attr_timeout{"",
                                      "attr-timeout",
                                      "Number of seconds to cache file attributes. Default is 30.",
                                      false,
                                      30,
                                      "int"};
    
private:
    // 将args从std::vector<std::string>转为std::vector<const char*>格式
    // 因为有些c库函数参数类型为char*
    // 函数参数vector传引用比传值更高效，避免了复制的开销
    std::vector<const char*> to_c_style_args(const std::vector<std::string>& args)
    {
        std::vector<const char*> result(args.size());
        std::transform(args.begin(),
                       args.end(),
                       result.begin(),
                       [](const std::string& s) { return s.c_str(); });
        return result;
    }
// 如果是windows系统，则编译下面几个函数
#ifdef WIN32
    // 判断一个字符是不是字母
    static bool is_letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
    // 判断挂载点是不是驱动挂载点
    static bool is_drive_mount(StringRef mount_point)
    {
        return mount_point.size() == 2 && is_letter(mount_point[0]) && mount_point[1] == ':';
    }
    // 判断挂载点是不是网络挂载点
    static bool is_network_mount(StringRef mount_point)
    {
        return mount_point.starts_with("\\\\") && !mount_point.starts_with("\\\\?\\");
    }
#endif

    // 用于输出verbose_log，将所有参数拼成一个字符串
    static std::string escape_args(const std::vector<std::string>& args)
    {
        std::string result;
        for (const auto& a : args)
        {
            // 把不能打印的字符特殊处理一下
            result.append(securefs::escape_nonprintable(a.data(), a.size()));
            result.push_back(' ');
        }
        if (!result.empty())
        {
            result.pop_back();
        }
        return result;
    }

public:
    // 解析命令函数
    void parse_cmdline(int argc, const char* const* argv) override
    {
        
        TCLAP::CmdLine cmdline(help_message());

#ifdef __APPLE__
        cmdline.add(&noxattr);
#endif
        // 添加基本参数到参数解析列表中
        add_all_args_from_base(cmdline);
        // 添加参数到参数解析列表中
        cmdline.add(&background);
        // cmdline.add(&insecure);
        cmdline.add(&verbose);
        cmdline.add(&trace);
        cmdline.add(&log);
        cmdline.add(&mount_point);
        cmdline.add(&fuse_options);
        cmdline.add(&single_threaded);
        cmdline.add(&normalization);
        cmdline.add(&fsname);
        cmdline.add(&fssubtype);
        cmdline.add(&noflock);
        cmdline.add(&attr_timeout);
        // 解析命令行，将参数对应的变量进行赋值
        cmdline.parse(argc, argv);

        // 作用：获取用户输入的密码或keyfile，以便后面在get_config()中验证
        // require_confirmation = false 表示不需要二次验证
        get_password(false);

        // 根据命令设置日志的等级
        if (global_logger && verbose.getValue())
            global_logger->set_level(kLogVerbose);
        if (global_logger && trace.getValue())
            global_logger->set_level(kLogTrace);

        // 设置是否开启flock锁
        // set_lock_enabled函数中的操作是原子操作
        set_lock_enabled(!noflock.getValue());
        // 如果禁用flock且不开启单线程模式，操作文件是危险的（因为读取用户挂载点的请求是多线程的，所以可能存在多线程操作同一个文件的情况，线程不安全）
        if (noflock.getValue() && !single_threaded.getValue())
        {
            WARN_LOG("Using --noflock without --single is highly dangerous");
        }
    }

    // 重新创建logger对象函数（根据命令设置log输出位置和等级）
    void recreate_logger()
    {
        // 判断是否设置开启log功能，开启了就是把log保存在本地
        if (log.isSet())
        {
            // 创建logger对象，用fopen()打开路径（不是系统调用），返回FILE对象
            auto logger = Logger::create_file_logger(log.getValue());
            // 释放global_logger（该对象在logger.cpp中创建，全局变量，using命名空间，所以可以直接用）
            delete global_logger;
            // global_logger指向新创建的logger
            global_logger = logger;
        }
        // 如果没有开启log功能，但是开启了后台运行功能
        else if (background.getValue())
        {
            // 警告最好启用log功能
            WARN_LOG("securefs is about to enter background without a log file. You "
                     "won't be able to inspect what goes wrong. You can remount with "
                     "option --log instead.");
            // 释放global_logger并置空
            delete global_logger;
            global_logger = nullptr;
        }
        // 若开启verbose功能，则将global_logger的level设为verbose
        if (global_logger && verbose.getValue())
            global_logger->set_level(kLogVerbose);
        // 若开启trace功能，则将global_logger的level设为trace
        // 开启trace功能后，所有级别log都会输出
        if (global_logger && trace.getValue())
            global_logger->set_level(kLogTrace);
    }

    // mount命令执行主函数
    int execute() override
    {
        // 判断数据目录和挂载点是不是同一个，如果是会输出警告
        if (data_dir.getValue() == mount_point.getValue())
        {
            WARN_LOG("Mounting a directory on itself may cause securefs to hang");
        }

// 如果是windows系统
#ifdef WIN32
        // 看是不是网络挂载点
        bool network_mount = is_network_mount(mount_point.getValue());
        // 如果既不是网络挂载点也不是驱动挂载点，则输出警告
        if (!network_mount && !is_drive_mount(mount_point.getValue()))
        {
            WARN_LOG("The mount point on Windows should be a drive path, such as Z:, or a network "
                     "mount like \\\\securefs\\abcde. Otherwise some "
                     "programs will get confused due to case sensitivity");
        }
// 不是windows那就是其他系统咯
#else
        // 这里进行了error捕捉，应该是挂载成功了也可能会出现error，所以捕捉下咯
        try
        {
            // 创建挂载点目录
            // OSService这个类是os服务类，用来进行os相关操作，分unix和windows实现
            OSService::get_default().mkdir(mount_point.getValue(), 0755);
        }
        catch (const std::exception& e)
        {
            // 提示用户挂载成功了就不用管这个提示
            VERBOSE_LOG("%s (ignore this error if mounting succeeds eventually)", e.what());
        }
#endif
        // 打开配置文件（.securefs.json），获得配置文件流
        std::shared_ptr<FileStream> config_stream;
        try
        {
            config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        }
        // 若不能打开，则抛出error并结束程序
        catch (const ExceptionBase& e)
        {
            if (e.error_number() == ENOENT)
            {
                ERROR_LOG("Encounter exception %s", e.what());
                ERROR_LOG(
                    "Config file %s does not exist. Perhaps you forget to run `create` command "
                    "first?",
                    get_real_config_path().c_str());
                return 19;
            }
            throw;
        }
        // 重要：读取配置文件（这里会进行密码和keyfile的验证）
        auto config = read_config(
            config_stream.get(), password.data(), password.size(), keyfile.getValue());
        // 读完把配置文件流指针置空，引用计数为0，会释放对象占用的内存
        config_stream.reset();
        // SecureWipeBuffer这个方法将password.data()这个缓冲区擦除置0（把旧数据擦除置0，更加安全）
        CryptoPP::SecureWipeBuffer(password.data(), password.size());
        // TODO:判断随机生成的主钥是不是脆弱的？？什么原理
        bool is_vulnerable = popcount(config.master_key.data(), config.master_key.size())
            <= config.master_key.size();
        // 如果是脆落的提示重新创建一个文件系统，并及时迁移数据
        if (is_vulnerable)
        {
            WARN_LOG(
                "%s",
                "Your filesystem is created by a vulnerable version of securefs.\n"
                "Please immediate migrate your old data to a newly created securefs filesystem,\n"
                "and remove all traces of old data to avoid information leakage!");
            fputs("Do you wish to continue with mounting? (y/n)", stdout);
            // stdin、stdout、stderr和FILE文件流都是有缓冲区的，当缓冲区满了数据才会放出来，使用fflush(文件流)可以将数据从缓冲区立即输出出来
            // https://blog.csdn.net/shulianghan/article/details/121388293
            fflush(stdout);
            if (getchar() != 'y')
                return 110;
        }

        // 尝试提高文件描述符的数量限制
        // TODO:这里的try catch实际是无效的，raise_fd_limit()中不会抛出异常？
        try
        {
            int fd_limit = OSService::raise_fd_limit();
            VERBOSE_LOG("Raising the number of file descriptor limit to %d", fd_limit);
        }
        catch (const std::exception& e)
        {
            WARN_LOG("Failure to raise the maximum file descriptor limit (%s: %s)",
                     get_type_name(e).get(),
                     e.what());
        }

        // 创建一个string类型的vector容器fuse_args，来存放fuse的设置参数
        // TODO:fuse的各个参数含义在哪查？
        std::vector<std::string> fuse_args{
            "securefs",
            "-o",
            "hard_remove",
            "-o",
            "fsname=" + fsname.getValue(),
            "-o",
            "subtype=" + fssubtype.getValue(),
            "-o",
            strprintf("entry_timeout=%d", attr_timeout.getValue()),
            "-o",
            strprintf("attr_timeout=%d", attr_timeout.getValue()),
            "-o",
            strprintf("negative_timeout=%d", attr_timeout.getValue()),
// 如果是windows系统，放一些windows要用的参数
#ifndef _WIN32
            "-o",
            "atomic_o_trunc",
#endif
        };
        // 如果打开了单线程模式（命令输入了--single）,在fuse_arg末尾放入一个"-s""
        if (single_threaded.getValue())
        {
            fuse_args.emplace_back("-s");
        }
        // 如果不是单线程模式
        else
        {
// window系统时
#ifdef _WIN32
            fuse_args.emplace_back("-o");
            fuse_args.emplace_back(
                // strprintf() 返回字符串“ThreadCount=当前系统支持的并发线程数”
                strprintf("ThreadCount=%d", 2 * std::thread::hardware_concurrency()));
#endif
        }
        // 如果没有开启在后台运行securefs，则将挂载操作在前台运行，在命令行中以进程的方式卡住
        if (!background.getValue())
            fuse_args.emplace_back("-f");

// 如果系统是apple系统的话
// 注意macfuse和libfuse有一些区别的，比如下面这个noappledouble参数
#ifdef __APPLE__
        // ::getenv()表示获取环境变量中对应的设置
        const char* copyfile_disable = ::getenv("COPYFILE_DISABLE");
        // copyfile_disable环境变量为true则不挂载.DS_Store等apple dot file
        // 但是我的电脑上是copyfile_disable环境变量为false，所以会挂载.DS_Store等apple dot file
        if (copyfile_disable)
        {
            VERBOSE_LOG("Mounting without .DS_Store and other apple dot files because "
                        "environmental "
                        "variable COPYFILE_DISABLE is set to \"%s\"",
                        copyfile_disable);
            fuse_args.emplace_back("-o");
            fuse_args.emplace_back("noappledouble");
        }
// 如果系统是windows系统的话
#elif _WIN32
        fuse_args.emplace_back("-ouid=-1,gid=-1,umask=0");
        // 是网络挂载点的话，获取挂载点前缀
        if (network_mount)
        {
            fuse_args.emplace_back("--VolumePrefix=" + mount_point.getValue().substr(1));
        }
        // 设置fuse超时时间
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(strprintf("FileInfoTimeout=%d", attr_timeout.getValue() * 1000));
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(strprintf("DirInfoTimeout=%d", attr_timeout.getValue() * 1000));
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(strprintf("EaTimeout=%d", attr_timeout.getValue() * 1000));
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(strprintf("VolumeInfoTimeout=%d", attr_timeout.getValue() * 1000));
// 如果是linux系统的话
#else
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back("big_writes");
#endif
        // 如果mount指令输入了附加的fuse_opions
        if (fuse_options.isSet())
        {
            // 将这些fuse_opions从字符串数组中取出，加入到fuse_args中
            for (const std::string& opt : fuse_options.getValue())
            {
                fuse_args.emplace_back("-o");
                fuse_args.emplace_back(opt);
            }
        }

#ifdef WIN32
        // TODO:这里的代码应该没有写全把
        if (!network_mount)
#endif
        // 把挂载点的路径加入到fuse_args中
        fuse_args.emplace_back(mount_point.getValue());
        // 打印 VERBOSE_LOG，输出文件系统的一些信息到终端
        VERBOSE_LOG("Filesystem parameters: format version %d, block size %u (bytes), iv size %u "
                    "(bytes)",
                    config.version,
                    config.block_size,
                    config.iv_size);

        // Master key不脆弱就可以在VERBOSE_LOG中输出
        if (!is_vulnerable)
        {
            VERBOSE_LOG("Master key: %s", hexify(config.master_key).c_str());
        }

        // 定义fsopt对象，包含与securefs挂载有关的属性和OSService对象
        // fsopt会传入到fuse中作为fuse_context->private_data，存在整个fuse生命周期中，以便fuse中的operation使用
        operations::MountOptions fsopt;
        // 进行fsopt相关属性的赋值
        // 创建与数据目录有关的OSService对象root
        fsopt.root = std::make_shared<OSService>(data_dir.getValue());
        fsopt.block_size = config.block_size;
        fsopt.iv_size = config.iv_size;
        fsopt.version = config.version;
        fsopt.master_key = config.master_key;
        // 如果version=3的话，设置存储时间戳标志，需要存储时间戳到元文件中（存储时间戳是为了跨云服务同步用）
        fsopt.flags = config.version != 3 ? 0 : kOptionStoreTime;
        // max_padding_size是为模糊所有文件的大小，要添加到所有文件的最大填充数。每个文件都有不同的填充。启用此功能会带来很大的性能成本。
        fsopt.max_padding_size = config.max_padding;
        // insecure为true表示开启了禁用完整性验证，若开启了，则将对应的标志位或上去
        // 这个功能实际没有用，因为没有解析insecure这个参数
        if (insecure.getValue())
            fsopt.flags.value() |= kOptionNoAuthentication;

        // 设置文件名的规范化形式
        // 在mac上默认是nfc，其他平台默认none
        bool case_insensitive = false;
        bool enable_nfc = false;
        if (normalization.getValue() == "nfc")
        {
            enable_nfc = true;
        }
        else if (normalization.getValue() == "casefold")
        {
            case_insensitive = true;
        }
        else if (normalization.getValue() == "casefold+nfc")
        {
            case_insensitive = true;
            enable_nfc = true;
        }
        else if (normalization.getValue() != "none")
        {
            throw_runtime_error("Invalid flag of --normalization: " + normalization.getValue());
        }
        // 如果case_insensitive=true
        // 不区分文件名大小写，linux、windows、macos上的系统都是不区分文件名大小写的，所以securefs最好与其保持一致
        if (case_insensitive)
        {
            INFO_LOG("Mounting as a case insensitive filesystem");
            // 将对应的标志位或到flags中
            fsopt.flags.value() |= kOptionCaseFoldFileName;
        }
        // 如果enable_nfc=true
        if (enable_nfc)
        {
            INFO_LOG("Mounting as a Unicode normalized filesystem");
            // 把文件名采用nfc规范化，或到flags中
            fsopt.flags.value() |= kOptionNFCFileName;
        }

        // 如果 启用的version < 4（即用的是Full format 1-3）会产生一个“.securefs.lock”文件
        // TODO:为什么不同的securefs进程会出现访问数据不一致的情况
        // 正确：“.securefs.lock”文件的作用是实现一个数据目录同时只能被一个securefs进程操作
        // 为什么？？？不同的securefs进程会出现访问数据不一致的情况（用RAM做缓存所导致的？？？），这样进行操作容易出错，所以要防止多个securefs进程操作同一个数据目录
        // 注意：lite format中的不同的securefs进程之间的数据是同步的（为什么是同步的？？？），所以允许多个securefs进程操作同一个数据目录
        if (config.version < 4)
        {
            try
            {
                // fsopt.root为一个OSService类型的shared_ptr
                // “.securefs.lock”文件的权限设置为创建&O_EXCL&读
                // 注意：O_EXCL表示打开的时候如果存在则返回错误信息
                // 返回一个FileStream的多态UnixFileStream对象
                fsopt.lock_stream = fsopt.root->open_file_stream(
                    securefs::operations::LOCK_FILENAME, O_CREAT | O_EXCL | O_RDONLY, 0644);
            }
            catch (const ExceptionBase& e)
            {
                // 创建“.securefs.lock”文件失败的时候报错
                ERROR_LOG("Encountering error %s when creating the lock file %s/%s.\n"
                          "Perhaps multiple securefs instances are trying to operate on a single "
                          "directory.\n"
                          "Close other instances, including on other machines, and try again.\n"
                          "Or remove the lock file manually if you are sure no other instances are "
                          "holding the lock.",
                          e.what(),
                          data_dir.getValue().c_str(),
                          securefs::operations::LOCK_FILENAME);
                // 捕获异常后，退出mount函数，即没有挂载成功
                return 18;
            }
        }

        // noxattr为禁用xattr属性，为true表示禁用
        // native_xattr表示是否开启xattr功能
        bool native_xattr = !noxattr.getValue();

// 如果是apple系统的话并开启了扩展属性功能，挂载的时候检查支不支持扩展属性
#ifdef __APPLE__
        // 如果xattr开启了
        if (native_xattr)
        {
            // fsopt.root是一个类指针，所以访问类中的成员要用 -> 
            // listxattr返回当前目录下的扩展属性的大小，有的话就>0
            // 这里用listxattr的作用主要是判断有没有扩展属性支持
            // .表示当前目录
            // ..表示上一级目录
            auto rc = fsopt.root->listxattr(".", nullptr, 0);
            // 如果调用xattr相关函数失败，则warning
            if (rc < 0)
            {
                fprintf(stderr,
                        "Warning: %s has no extended attribute support.\nXattr is disabled\n",
                        data_dir.getValue().c_str());
                native_xattr = false;
            }
        }
#endif
        // 如果启用的version=1-3，则
        // fuse_operations是库fuse.h中定义的结构体，里面有基本的操作函数
        // 不同的version用到的基本操作函数不同，所以需要进行version判断
        struct fuse_operations operations;
        if (config.version <= 3)
        {
            // operations命名空间中的init_fuse_operations函数
            // 初始化fuse_operation，实现fuse定义的函数集，xattr参数用于判断要不要实现与xattr有关的operation
            operations::init_fuse_operations(&operations, native_xattr);
        }
        // 如果启用的version=4，则fuse基本操作应该用lite版
        else
        {
            // lite命名空间中的init_fuse_operations函数
            // 初始化fuse_operation，实现fuse定义的函数集，xattr参数用于判断要不要实现与xattr有关的operation
            lite::init_fuse_operations(&operations, native_xattr);
        }
        // VERBOSE_LOG，输出设置的所有fuse参数
        VERBOSE_LOG("Calling fuse_main with arguments: %s", escape_args(fuse_args).c_str());
        // 重新创建logger对象函数（根据命令设置log输出位置和等级）
        // 在执行这个函数之前的logger一定是在程序启动时，输出在控制台的
        // 只有与fuse的operation有关的log有可能存在文件里，启动前（fuse启动前的代码）的log都是在控制台输出
        recreate_logger();
        // 利用fuse_main函数和重写high_level的api来实现自己的用户级文件系统（如果用low_level可以实现更灵活的功能，但是需要读懂fuse源码）
        // fuse_main函数中的fuse_args在前面已经构造好了，包括挂载点、option等
        return fuse_main(static_cast<int>(fuse_args.size()),
                         const_cast<char**>(to_c_style_args(fuse_args).data()),
                         &operations,
                         &fsopt);
    }

    // const表示该方法只读；noexcept表示方法不会抛出异常，一旦有异常会终止程序；override表示方法覆盖
    const char* long_name() const noexcept override { return "mount"; }

    char short_name() const noexcept override { return 'm'; }

    const char* help_message() const noexcept override { return "Mount an existing filesystem"; }
};

// fix命令类，继承 _SinglePasswordCommandBase类
class FixCommand : public _SinglePasswordCommandBase
{
public:
    // 解析命令函数
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        add_all_args_from_base(cmdline);
        cmdline.parse(argc, argv);

        // 先强制输出stdout，防止出错
        fflush(stdout);
        // 先强制输出stderr，防止出错
        fflush(stderr);
        // 在命令行输出内容
        puts("You should backup your repository before running this command. Are you sure you want "
             "to continue? (yes/no)");
        // 先强制输出stdout，防止出错
        fflush(stdout);
        // answer用来获取用户输入
        char answer[100] = {};
        // 如果出错抛出异常
        if (fgets(answer, 100, stdin) == nullptr)
        {
            THROW_POSIX_EXCEPTION(errno, "fgets");
        }
        // 如果不是yes，则退出
        if (strcmp(answer, "yes\n") != 0)
        {
            throw_runtime_error("User aborted operation");
        }
        // 获取用户输入的密码，不需要二次验证，存放在password属性中
        get_password(false);
    }

    // fix命令执行主函数
    int execute() override
    {
        // 获得系统配置（master_key等）（只有当password正确才能正确运行，所以这里有验证密码的功能）
        auto config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        auto config = read_config(
            config_stream.get(), password.data(), password.size(), keyfile.getValue());
        config_stream.reset();

        // 如果format >= 4，则报错不支持修复，即只有format为1、2、3才可以修复
        if (config.version >= 4)
        {
            fprintf(stderr,
                    "The filesystem has format version %u which cannot be fixed\n",
                    config.version);
            return 3;
        }

        // 将用户输入的password擦除，重新随机生成
        generate_random(password.data(), password.size());    // Erase user input

        // 创建MountOptions结构体变量，将用户输入的datadir和原配置文件中的信息放进去
        operations::MountOptions fsopt;
        fsopt.root = std::make_shared<OSService>(data_dir.getValue());

        // 加flock锁，直至运行结束，别的尝试flock的线程不能对data_dir目录进行操作
        // 防止不同的securefs线程在对data_dir目录进行操作
        fsopt.root->lock();

        fsopt.block_size = config.block_size;
        fsopt.iv_size = config.iv_size;
        fsopt.version = config.version;
        fsopt.master_key = config.master_key;
        fsopt.flags = config.version != 3 ? 0 : kOptionStoreTime;
        
        // 创建FileSystemContext文件系统上下文对象
        operations::FileSystemContext fs(fsopt);
        // 利用data_dir路径和FileSystemContext对象进行修复
        fix(data_dir.getValue(), &fs);
        return 0;
    }

    const char* long_name() const noexcept override { return "fix"; }

    char short_name() const noexcept override { return 0; }

    const char* help_message() const noexcept override
    {
        return "Try to fix errors in an existing filesystem";
    }
};

static inline const char* true_or_false(bool v) { return v ? "true" : "false"; }

// version命令类，继承自CommandBase类
class VersionCommand : public CommandBase
{
public:
    // 解析命令函数
    void parse_cmdline(int argc, const char* const* argv) override
    {
        (void)argc;
        (void)argv;
    }

    // version命令执行主函数
    int execute() override
    {
        using namespace CryptoPP;
        // 输出securefs的版本，利用引入的cmake-modules获取
        printf("securefs %s\n", GIT_VERSION);
        // 输出Crypto++的版本，利用cryptopp中定义的宏获取
        printf("Crypto++ %g\n", CRYPTOPP_VERSION / 100.0);
// 如果是windows系统，输出WinFsp版本
#ifdef WIN32
        HMODULE hd = GetModuleHandleW((sizeof(void*) == 8) ? L"winfsp-x64.dll" : L"winfsp-x86.dll");
        NTSTATUS(*fsp_version_func)
        (uint32_t*) = get_proc_address<decltype(fsp_version_func)>(hd, "FspVersion");
        if (fsp_version_func)
        {
            uint32_t vn;
            if (fsp_version_func(&vn) == 0)
            {
                printf("WinFsp %u.%u\n", vn >> 16, vn & 0xFFFFu);
            }
        }
#else   // 如果是unix系统，输出libfuse版本
        typedef int version_function(void);
        auto fuse_version_func
            = reinterpret_cast<version_function*>(::dlsym(RTLD_DEFAULT, "fuse_version"));
        printf("libfuse %d\n", fuse_version_func());
#endif
        // 输出utf8proc的版本
        // utf8proc是unicode编码工具，应该是用来对文件数据进行编码解码用的
        printf("utf8proc %s\n", utf8proc_version());

// 输出是否有硬件特性支持加密，有硬件支持的话加解密会更快
#ifdef CRYPTOPP_DISABLE_ASM
        fputs("\nBuilt without hardware acceleration\n", stdout);
#else
// 有硬件特性支持加密且符合cpu架构，执行相应测试函数并输出测试结果
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
        printf("\nHardware features available:\nSSE2: %s\nSSE3: %s\nSSE4.1: %s\nSSE4.2: "
               "%s\nAES-NI: %s\nCLMUL: %s\nSHA: %s\n",
               HasSSE2() ? "true" : "false",
               HasSSSE3() ? "true" : "false",
               HasSSE41() ? "true" : "false",
               HasSSE42() ? "true" : "false",
               HasAESNI() ? "true" : "false",
               HasCLMUL() ? "true" : "false",
               HasSHA() ? "true" : "false");
#endif
#endif
        return 0;
    }

    const char* long_name() const noexcept override { return "version"; }

    char short_name() const noexcept override { return 'v'; }

    const char* help_message() const noexcept override { return "Show version of the program"; }
};

class InfoCommand : public CommandBase
{
private:
    // path表示文件系统所在目录或配置文件的完全路径
    TCLAP::UnlabeledValueArg<std::string> path{
        "path", "Directory or the filename of the config file", true, "", "path"};

public:
    // 解析命令函数
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&path);
        cmdline.parse(argc, argv);
    }

    const char* long_name() const noexcept override { return "info"; }

    char short_name() const noexcept override { return 'i'; }

    const char* help_message() const noexcept override
    {
        return "Display information about the filesystem";
    }

    // info命令执行函数
    int execute() override
    {
        // 创建FileStream对象shared_ptr
        std::shared_ptr<FileStream> fs;
        struct fuse_stat st;
        // 判断用户输入路径是不是存在
        if (!OSService::get_default().stat(path.getValue(), &st))
        {
            ERROR_LOG("The path %s does not exist.", path.getValue().c_str());
        }

        // 获得刚刚输入的path
        std::string real_config_path = path.getValue();
        // 如果输入的path是目录，则加上配置文件名，得到配置文件完成路径
        // unix或linux环境编程要会搞，才写得出这个代码
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            real_config_path.append("/.securefs.json");
        // 赋值FileStream对象shared_ptr
        fs = OSService::get_default().open_file_stream(real_config_path, O_RDONLY, 0);

        // 将配置文件流解析成JSON
        Json::Value config_json;
        // Open a new scope to limit the lifetime of `buffer`.
        // 创建一个新的作用域来限制buffer生命周期
        {
            std::vector<char> buffer(fs->size(), 0);
            fs->read(buffer.data(), 0, buffer.size());
            std::string error_message;
            // 创建json读取对象，并对buffer按char进行解析，将结果放到config_json中
            if (!create_json_reader()->parse(
                    buffer.data(), buffer.data() + buffer.size(), &config_json, &error_message))
            {
                throw_runtime_error(
                    strprintf("Failure to parse the config file: %s", error_message.c_str()));
            }
        }

        // 输出配置文件信息
        unsigned format_version = config_json["version"].asUInt();
        if (format_version < 1 || format_version > 4)
        {
            ERROR_LOG("Unknown filesystem format version %u", format_version);
            return 44;
        }
        printf("Config file path: %s\n", real_config_path.c_str());
        printf("Filesystem format version: %u\n", format_version);
        printf("Is full or lite format: %s\n", (format_version < 4) ? "full" : "lite");
        printf("Is underlying directory flattened: %s\n", true_or_false(format_version < 4));
        printf("Is multiple mounts allowed: %s\n", true_or_false(format_version >= 4));
        printf("Is timestamp stored within the fs: %s\n\n", true_or_false(format_version == 3));

        printf("Content block size: %u bytes\n",
               format_version == 1 ? 4096 : config_json["block_size"].asUInt());
        printf("Content IV size: %u bits\n",
               format_version == 1 ? 256 : config_json["iv_size"].asUInt() * 8);
        printf("Password derivation algorithm: %s\n",
               config_json.get("pbkdf", PBKDF_ALGO_PKCS5).asCString());
        printf("Password derivation iterations: %u\n", config_json["iterations"].asUInt());
        printf("Per file key generation algorithm: %s\n",
               format_version < 4 ? "HMAC-SHA256" : "AES");
        printf("Content cipher: %s\n", format_version < 4 ? "AES-256-GCM" : "AES-128-GCM");
        return 0;
    }
};

// commands_main函数用来实现命令行操作，securefs系统的实现通过这些命令完成
int commands_main(int argc, const char* const* argv)
{
    try
    {
        // 取消c++和c公用缓冲区写读流同步，可以加快c++中cin和cout的处理速度
        std::ios_base::sync_with_stdio(false);
        // unique_ptr这种类型的指针不能共享，不能传递，只能转移
        // 用到了多态，MountCommand等继承了CommandBase
        // 创建CommandBase类的unique_ptr数组，存放了MountCommand、CreateCommand等对象的指针
        std::unique_ptr<CommandBase> cmds[] = {make_unique<MountCommand>(),
                                               make_unique<CreateCommand>(),
                                               make_unique<ChangePasswordCommand>(),
                                               make_unique<FixCommand>(),
                                               make_unique<VersionCommand>(),
                                               make_unique<InfoCommand>()};
        // program_name为当前运行的程序的路径
        const char* const program_name = argv[0];

        // 输出可用的命令命令
        // 匿名函数，[&]表示以引用形式捕获所有外部变量，也就是外部变量均可用
        auto print_usage = [&]()
        {
            // 将字符串放到标准错误流中，用于写入诊断输出。程序启动时，该流不为完全缓冲，默认向屏幕输出。
            // 没有以正确的形式使用的时候输出这些东西，所以用stderr
            fputs("Available subcommands:\n\n", stderr);

            // auto&& ：不创建拷贝，可以修改元素的值
            for (auto&& command : cmds)
            {
                // 输出各条命令的信息到stderr
                if (command->short_name())
                {
                    fprintf(stderr,
                            "%s (alias: %c): %s\n",
                            command->long_name(),
                            command->short_name(),
                            command->help_message());
                }
                else
                {
                    fprintf(stderr, "%s: %s\n", command->long_name(), command->help_message());
                }
            }
            // 输出最后一条help提示
            fprintf(stderr, "\nType %s ${SUBCOMMAND} --help for details\n", program_name);
            // main函数返回1表示程序异常退出
            return 1;
        };

        // 如果程序后面没有跟参数的话，调用print_usage()输出提示信息就结束程序
        if (argc < 2)
            return print_usage();
        
        // 把第一个参数（程序路径去掉）
        argc--;
        argv++;

        // 遍历unique_ptr数组，获得数组里面的每个元素（因为是unique_ptr，必须要带&，才能获取到引用，可以修改元素的值）
        for (std::unique_ptr<CommandBase>& command : cmds)
        {   
            // 匹配命令
            if (strcmp(argv[0], command->long_name()) == 0
                || (argv[0] != nullptr && argv[0][0] == command->short_name() && argv[0][1] == 0))
            {
                // 匹配到的命令进行命令的解析（解析后，输入的命令参数对应的变量才能获得对应的值）
                command->parse_cmdline(argc, argv);
                // 执行命令（根据获取到命令参数对应的变量的值来进行操作）
                return command->execute();
            }
        }
        // 执行输出可用命令的匿名函数
        return print_usage();
    }
    // 参数解析异常提示
    // 根据不同的异常，输出不同的ERROR_LOG，并结束程序
    // https://tclap.sourceforge.net/html/classTCLAP_1_1ArgException.html
    catch (const TCLAP::ArgException& e)
    {
        ERROR_LOG("Error parsing arguments: %s at %s\n", e.error().c_str(), e.argId().c_str());
        return 5;
    }
    catch (const std::runtime_error& e)
    {
        ERROR_LOG("%s\n", e.what());
        return 1;
    }
    catch (const std::exception& e)
    {
        ERROR_LOG("%s: %s\n", get_type_name(e).get(), e.what());
        return 2;
    }
}
}    // namespace securefs
