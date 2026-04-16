// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallettool.h>

#include <common/args.h>
#include <fstream>
#include <script/descriptor.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/translation.h>
#include <wallet/dump.h>
#include <wallet/encryptedbackup.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

namespace wallet {
namespace WalletTool {

static util::Result<EncryptedBackup> ReadBackupFromArgsOrStdin(const ArgsManager& args)
{
    const std::string backup_filename = args.GetArg("-backupfile", "");
    if (!backup_filename.empty()) {
        fs::path in_path = fs::absolute(fs::PathFromString(backup_filename));
        std::ifstream in_file(in_path.std_path(), std::ios::binary);
        if (in_file.fail()) {
            return util::Error{Untranslated(strprintf("Unable to open %s for reading", fs::PathToString(in_path)))};
        }
        std::vector<uint8_t> binary_input((std::istreambuf_iterator<char>(in_file)),
                                          std::istreambuf_iterator<char>());
        if (binary_input.empty()) {
            return util::Error{Untranslated(strprintf("Backup file %s is empty.", fs::PathToString(in_path)))};
        }
        return DecodeEncryptedBackup(binary_input);
    }
    std::string base64_input;
    std::getline(std::cin, base64_input);
    if (base64_input.empty()) {
        return util::Error{Untranslated("No backup data provided on stdin.")};
    }
    return DecodeEncryptedBackupBase64(base64_input);
}

static util::Result<std::string> ReadAndDecryptBackup(const ArgsManager& args)
{
    if (!args.IsArgSet("-xpub")) {
        return util::Error{Untranslated("Extended public key must be provided via -xpub.")};
    }

    auto backup_result = ReadBackupFromArgsOrStdin(args);
    if (!backup_result) {
        return util::Error{util::ErrorString(backup_result)};
    }

    return DecryptDescriptorWithXpub(*backup_result, args.GetArg("-xpub", ""));
}


// The standard wallet deleter function blocks on the validation interface
// queue, which doesn't exist for the bitcoin-wallet. Define our own
// deleter here.
static void WalletToolReleaseWallet(CWallet* wallet)
{
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->Close();
    delete wallet;
}

static void WalletCreate(CWallet* wallet_instance, uint64_t wallet_creation_flags)
{
    LOCK(wallet_instance->cs_wallet);

    wallet_instance->InitWalletFlags(wallet_creation_flags);

    Assert(wallet_instance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    wallet_instance->SetupDescriptorScriptPubKeyMans();

    tfm::format(std::cout, "Topping up keypool...\n");
    wallet_instance->TopUpKeyPool();
}

static std::shared_ptr<CWallet> MakeWallet(const std::string& name, const fs::path& path, DatabaseOptions options)
{
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    std::unique_ptr<WalletDatabase> database = MakeDatabase(path, options, status, error);
    if (!database) {
        tfm::format(std::cerr, "%s\n", error.original);
        return nullptr;
    }

    // dummy chain interface
    std::shared_ptr<CWallet> wallet_instance{new CWallet(/*chain=*/nullptr, name, std::move(database)), WalletToolReleaseWallet};
    DBErrors load_wallet_ret;
    try {
        load_wallet_ret = wallet_instance->PopulateWalletFromDB(error, warnings);
    } catch (const std::runtime_error&) {
        tfm::format(std::cerr, "Error loading %s. Is wallet being used by another process?\n", name);
        return nullptr;
    }

    if (!error.empty()) {
        tfm::format(std::cerr, "%s", error.original);
    }

    for (const auto &warning : warnings) {
        tfm::format(std::cerr, "%s", warning.original);
    }

    if (load_wallet_ret != DBErrors::LOAD_OK && load_wallet_ret != DBErrors::NONCRITICAL_ERROR && load_wallet_ret != DBErrors::NEED_RESCAN) {
        return nullptr;
    }

    if (options.require_create) WalletCreate(wallet_instance.get(), options.create_flags);

    return wallet_instance;
}

static void WalletShowInfo(CWallet* wallet_instance)
{
    LOCK(wallet_instance->cs_wallet);

    tfm::format(std::cout, "Wallet info\n===========\n");
    tfm::format(std::cout, "Name: %s\n", wallet_instance->GetName());
    tfm::format(std::cout, "Format: %s\n", wallet_instance->GetDatabase().Format());
    tfm::format(std::cout, "Descriptors: %s\n", wallet_instance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) ? "yes" : "no");
    tfm::format(std::cout, "Encrypted: %s\n", wallet_instance->HasEncryptionKeys() ? "yes" : "no");
    tfm::format(std::cout, "HD (hd seed available): %s\n", wallet_instance->IsHDEnabled() ? "yes" : "no");
    tfm::format(std::cout, "Keypool Size: %u\n", wallet_instance->GetKeyPoolSize());
    tfm::format(std::cout, "Transactions: %zu\n", wallet_instance->mapWallet.size());
    tfm::format(std::cout, "Address Book: %zu\n", wallet_instance->m_address_book.size());
}

bool ExecuteWalletToolFunc(const ArgsManager& args, const std::string& command)
{
    if (args.IsArgSet("-dumpfile") && command != "dump" && command != "createfromdump") {
        tfm::format(std::cerr, "The -dumpfile option can only be used with the \"dump\" and \"createfromdump\" commands.\n");
        return false;
    }
    if (args.IsArgSet("-backupfile") && command != "encryptdescriptor" && command != "decryptdescriptor") {
        tfm::format(std::cerr, "The -backupfile option can only be used with the \"encryptdescriptor\" and \"decryptdescriptor\" commands.\n");
        return false;
    }
    if ((command == "create" || command == "createfromdump") && !args.IsArgSet("-wallet")) {
        tfm::format(std::cerr, "Wallet name must be provided when creating a new wallet.\n");
        return false;
    }
    const std::string name = args.GetArg("-wallet", "");
    const fs::path path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(name));

    if (command == "create") {
        if (name.empty()) {
            tfm::format(std::cerr, "Wallet name cannot be empty\n");
            return false;
        }
        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_create = true;
        options.create_flags |= WALLET_FLAG_DESCRIPTORS;
        options.require_format = DatabaseFormat::SQLITE;

        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (wallet_instance) {
            WalletShowInfo(wallet_instance.get());
            wallet_instance->Close();
        }
    } else if (command == "info") {
        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (!wallet_instance) return false;
        WalletShowInfo(wallet_instance.get());
        wallet_instance->Close();
    } else if (command == "dump") {
        DatabaseOptions options;
        ReadDatabaseArgs(args, options);
        options.require_existing = true;
        DatabaseStatus status;

        if (IsBDBFile(BDBDataFile(path))) {
            options.require_format = DatabaseFormat::BERKELEY_RO;
        }

        bilingual_str error;
        std::unique_ptr<WalletDatabase> database = MakeDatabase(path, options, status, error);
        if (!database) {
            tfm::format(std::cerr, "%s\n", error.original);
            return false;
        }

        bool ret = DumpWallet(args, *database, error);
        if (!ret && !error.empty()) {
            tfm::format(std::cerr, "%s\n", error.original);
            return ret;
        }
        tfm::format(std::cout, "The dumpfile may contain private keys. To ensure the safety of your Bitcoin, do not share the dumpfile.\n");
        return ret;
    } else if (command == "createfromdump") {
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        bool ret = CreateFromDump(args, name, path, error, warnings);
        for (const auto& warning : warnings) {
            tfm::format(std::cout, "%s\n", warning.original);
        }
        if (!ret && !error.empty()) {
            tfm::format(std::cerr, "%s\n", error.original);
        }
        return ret;
    } else if (command == "encryptdescriptor") {
        // Encrypt a descriptor string using BIP-XXXX encrypted backup format
        if (!args.IsArgSet("-descriptor")) {
            tfm::format(std::cerr, "Descriptor string must be provided via -descriptor for encryptdescriptor.\n");
            return false;
        }
        const std::string descriptor = args.GetArg("-descriptor", "");

        // Validate the descriptor parses and has a checksum
        FlatSigningProvider keys;
        std::string parse_error;
        auto parsed = Parse(descriptor, keys, parse_error, /*require_checksum=*/true);
        if (parsed.empty()) {
            tfm::format(std::cerr, "Invalid descriptor: %s\n", parse_error);
            return false;
        }

        // Plaintext is the raw descriptor string
        std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());

        auto extract_result = ExtractKeysFromDescriptor(descriptor);
        if (!extract_result) {
            tfm::format(std::cerr, "Failed to extract keys: %s\n",
                        util::ErrorString(extract_result).original);
            return false;
        }
        auto& [encryption_keys, derivation_paths] = *extract_result;

        // Create backup content metadata
        EncryptedBackupContent content;
        content.type = ContentType::BIP_NUMBER;
        content.bip_number = BIP_DESCRIPTORS;

        // Create the encrypted backup
        auto backup_result = CreateEncryptedBackup(encryption_keys, plaintext, content, derivation_paths);
        if (!backup_result) {
            tfm::format(std::cerr, "Failed to create encrypted backup: %s\n",
                        util::ErrorString(backup_result).original);
            return false;
        }

        // If -backupfile is set, write raw binary backup to that file. Otherwise output base64 to stdout.
        const std::string backup_filename = args.GetArg("-backupfile", "");
        if (!backup_filename.empty()) {
            fs::path out_path = fs::absolute(fs::PathFromString(backup_filename));
            if (fs::exists(out_path)) {
                tfm::format(std::cerr, "File %s already exists. If you are sure this is what you want, move it out of the way first.\n", fs::PathToString(out_path));
                return false;
            }
            auto binary_backup = EncodeEncryptedBackup(*backup_result);
            if (!binary_backup) {
                tfm::format(std::cerr, "Error encoding backup: %s\n", util::ErrorString(binary_backup).original);
                return false;
            }
            std::ofstream out_file(out_path.std_path(), std::ios::binary);
            if (out_file.fail()) {
                tfm::format(std::cerr, "Unable to open %s for writing\n", fs::PathToString(out_path));
                return false;
            }
            out_file.write(reinterpret_cast<const char*>(binary_backup->data()), binary_backup->size());
            if (out_file.fail()) {
                tfm::format(std::cerr, "Error writing backup to %s\n", fs::PathToString(out_path));
                return false;
            }
        } else {
            auto base64_backup = EncodeEncryptedBackupBase64(*backup_result);
            if (!base64_backup) {
                tfm::format(std::cerr, "Error encoding backup: %s\n", util::ErrorString(base64_backup).original);
                return false;
            }
            tfm::format(std::cout, "%s\n", *base64_backup);
        }
    } else if (command == "decryptdescriptor") {
        // Decrypt an encrypted backup using a provided extended public key
        auto descriptor = ReadAndDecryptBackup(args);
        if (!descriptor) {
            tfm::format(std::cerr, "%s\n", util::ErrorString(descriptor).original);
            return false;
        }

        tfm::format(std::cout, "%s\n", *descriptor);
    } else {
        tfm::format(std::cerr, "Invalid command: %s\n", command);
        return false;
    }

    return true;
}
} // namespace WalletTool
} // namespace wallet
