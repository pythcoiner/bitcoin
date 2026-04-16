// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/protocol.h"
#include <chain.h>
#include <clientversion.h>
#include <core_io.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <merkleblock.h>
#include <node/types.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/solver.h>
#include <sync.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/encryptedbackup.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <cstdint>
#include <fstream>
#include <optional>
#include <tuple>
#include <string>

#include <univalue.h>



using interfaces::FoundBlock;

namespace wallet {
RPCMethod importprunedfunds()
{
    return RPCMethod{
        "importprunedfunds",
        "Imports funds without rescan. Corresponding address or script must previously be included in wallet. Aimed towards pruned wallets. The end-user is responsible to import additional transactions that subsequently spend the imported outputs or rescan after the point in the blockchain the transaction is included.\n",
                {
                    {"rawtransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A raw transaction in hex funding an already-existing address in wallet"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex output from gettxoutproof that contains the transaction"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{""},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    CMerkleBlock merkleBlock;
    SpanReader{ParseHexV(request.params[1], "proof")} >> merkleBlock;

    //Search partial merkle tree in proof for our transaction and index in valid block
    std::vector<Txid> vMatch;
    std::vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Something wrong with merkleblock");
    }

    LOCK(pwallet->cs_wallet);
    int height;
    if (!pwallet->chain().findAncestorByHash(pwallet->GetLastBlockHash(), merkleBlock.header.GetHash(), FoundBlock().height(height))) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
    }

    std::vector<Txid>::const_iterator it;
    if ((it = std::find(vMatch.begin(), vMatch.end(), tx.GetHash())) == vMatch.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction given doesn't exist in proof");
    }

    unsigned int txnIndex = vIndex[it - vMatch.begin()];

    CTransactionRef tx_ref = MakeTransactionRef(tx);
    if (pwallet->IsMine(*tx_ref)) {
        pwallet->AddToWallet(std::move(tx_ref), TxStateConfirmed{merkleBlock.header.GetHash(), height, static_cast<int>(txnIndex)});
        return UniValue::VNULL;
    }

    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No addresses in wallet correspond to included transaction");
},
    };
}

RPCMethod removeprunedfunds()
{
    return RPCMethod{
        "removeprunedfunds",
        "Deletes the specified transaction from the wallet. Meant for use with pruned wallets and as a companion to importprunedfunds. This will affect wallet balances.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded id of the transaction you are deleting"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("removeprunedfunds", "\"a8d0c0184dde994a09ec054286f1ce581bebf46446a512166eae7628734ea0a5\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
    std::vector<Txid> vHash;
    vHash.push_back(hash);
    if (auto res = pwallet->RemoveTxs(vHash); !res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
    }

    return UniValue::VNULL;
},
    };
}

static int64_t GetImportTimestamp(const UniValue& data, int64_t now)
{
    if (data.exists("timestamp")) {
        const UniValue& timestamp = data["timestamp"];
        if (timestamp.isNum()) {
            return timestamp.getInt<int64_t>();
        } else if (timestamp.isStr() && timestamp.get_str() == "now") {
            return now;
        }
        throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected number or \"now\" timestamp value for key. got type %s", uvTypeName(timestamp.type())));
    }
    throw JSONRPCError(RPC_TYPE_ERROR, "Missing required timestamp field for key");
}

static UniValue ProcessDescriptorImport(CWallet& wallet, const UniValue& data, const int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue warnings(UniValue::VARR);
    UniValue result(UniValue::VOBJ);

    try {
        if (!data.exists("desc")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor not found.");
        }

        const std::string& descriptor = data["desc"].get_str();
        const bool active = data.exists("active") ? data["active"].get_bool() : false;
        const std::string label{LabelFromValue(data["label"])};

        // Parse descriptor string
        FlatSigningProvider keys;
        std::string error;
        auto parsed_descs = Parse(descriptor, keys, error, /* require_checksum = */ true);
        if (parsed_descs.empty()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
        }
        std::optional<bool> internal;
        if (data.exists("internal")) {
            if (parsed_descs.size() > 1) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot have multipath descriptor while also specifying \'internal\'");
            }
            internal = data["internal"].get_bool();
        }

        // Range check
        std::optional<bool> is_ranged;
        int64_t range_start = 0, range_end = 1, next_index = 0;
        if (!parsed_descs.at(0)->IsRange() && data.exists("range")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
        } else if (parsed_descs.at(0)->IsRange()) {
            if (data.exists("range")) {
                auto range = ParseDescriptorRange(data["range"]);
                range_start = range.first;
                range_end = range.second + 1; // Specified range end is inclusive, but we need range end as exclusive
            } else {
                warnings.push_back("Range not given, using default keypool range");
                range_start = 0;
                range_end = wallet.m_keypool_size;
            }
            next_index = range_start;
            is_ranged = true;

            if (data.exists("next_index")) {
                next_index = data["next_index"].getInt<int64_t>();
                // bound checks
                if (next_index < range_start || next_index >= range_end) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "next_index is out of range");
                }
            }
        }

        // Active descriptors must be ranged
        if (active && !parsed_descs.at(0)->IsRange()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Active descriptors must be ranged");
        }

        // Multipath descriptors should not have a label
        if (parsed_descs.size() > 1 && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptors should not have a label");
        }

        // Ranged descriptors should not have a label
        if (is_ranged.has_value() && is_ranged.value() && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptors should not have a label");
        }

        bool desc_internal = internal.has_value() && internal.value();
        // Internal addresses should not have a label either
        if (desc_internal && data.exists("label")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Internal addresses should not have a label");
        }

        // Combo descriptor check
        if (active && !parsed_descs.at(0)->IsSingleType()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Combo descriptors cannot be set to active");
        }

        // If the wallet disabled private keys, abort if private keys exist
        if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !keys.keys.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import private keys to a wallet with private keys disabled");
        }

        for (size_t j = 0; j < parsed_descs.size(); ++j) {
            auto parsed_desc = std::move(parsed_descs[j]);
            if (parsed_descs.size() == 2) {
                desc_internal = j == 1;
            } else if (parsed_descs.size() > 2) {
                CHECK_NONFATAL(!desc_internal);
            }
            // Need to ExpandPrivate to check if private keys are available for all pubkeys
            FlatSigningProvider expand_keys;
            std::vector<CScript> scripts;
            if (!parsed_desc->Expand(0, keys, scripts, expand_keys)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot expand descriptor. Probably because of hardened derivations without private keys provided");
            }
            parsed_desc->ExpandPrivate(0, keys, expand_keys);

            for (const auto& w : parsed_desc->Warnings()) {
               warnings.push_back(w);
            }

            // Check if all private keys are provided
            bool have_all_privkeys = !expand_keys.keys.empty();
            for (const auto& entry : expand_keys.origins) {
                const CKeyID& key_id = entry.first;
                CKey key;
                if (!expand_keys.GetKey(key_id, key)) {
                    have_all_privkeys = false;
                    break;
                }
            }

            // If private keys are enabled, check some things.
            if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
               if (keys.keys.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import descriptor without private keys to a wallet with private keys enabled");
               }
               if (!have_all_privkeys) {
                   warnings.push_back("Not all private keys provided. Some wallet functionality may return unexpected errors");
               }
            }

            WalletDescriptor w_desc(std::move(parsed_desc), timestamp, range_start, range_end, next_index);

            // Add descriptor to the wallet
            auto spk_manager_res = wallet.AddWalletDescriptor(w_desc, keys, label, desc_internal);

            if (!spk_manager_res) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Could not add descriptor '%s': %s", descriptor, util::ErrorString(spk_manager_res).original));
            }

            auto& spk_manager = spk_manager_res.value().get();

            // Set descriptor as active if necessary
            if (active) {
                if (!w_desc.descriptor->GetOutputType()) {
                    warnings.push_back("Unknown output type, cannot set descriptor to active.");
                } else {
                    wallet.AddActiveScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            } else {
                if (w_desc.descriptor->GetOutputType()) {
                    wallet.DeactivateScriptPubKeyMan(spk_manager.GetID(), *w_desc.descriptor->GetOutputType(), desc_internal);
                }
            }
        }

        result.pushKV("success", UniValue(true));
    } catch (const UniValue& e) {
        result.pushKV("success", UniValue(false));
        result.pushKV("error", e);
    }
    PushWarnings(warnings, result);
    return result;
}

RPCMethod importdescriptors()
{
    return RPCMethod{
        "importdescriptors",
        "Import descriptors. This will trigger a rescan of the blockchain based on the earliest timestamp of all descriptors being imported. Requires a new wallet backup.\n"
        "When importing descriptors with multipath key expressions, if the multipath specifier contains exactly two elements, the descriptor produced from the second element will be imported as an internal descriptor.\n"
            "\nNote: This call can take over an hour to complete if using an early timestamp; during that time, other rpc calls\n"
            "may report that the imported keys, addresses or scripts exist but related transactions are still missing.\n"
            "The rescan is significantly faster if block filters are available (using startup option \"-blockfilterindex=1\").\n",
                {
                    {"requests", RPCArg::Type::ARR, RPCArg::Optional::NO, "Data to be imported",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "Descriptor to import."},
                                    {"active", RPCArg::Type::BOOL, RPCArg::Default{false}, "Set this descriptor to be the active descriptor for the corresponding output type/externality"},
                                    {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED, "If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import"},
                                    {"next_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If a ranged descriptor is set to active, this specifies the next index to generate addresses from"},
                                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, "Time from which to start rescanning the blockchain for this descriptor, in " + UNIX_EPOCH_TIME + "\n"
                                        "Use the string \"now\" to substitute the current synced blockchain time.\n"
                                        "\"now\" can be specified to bypass scanning, for outputs which are known to never have been used, and\n"
                                        "0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp\n"
                                        "of all descriptors being imported will be scanned as well as the mempool.",
                                        RPCArgOptions{.type_str={"timestamp | \"now\"", "integer / string"}}
                                    },
                                    {"internal", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether matching outputs should be treated as not incoming payments (e.g. change)"},
                                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Label to assign to the address, only allowed with internal=false. Disabled for ranged descriptors"},
                                },
                            },
                        },
                        RPCArgOptions{.oneline_description="requests"}},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "Response is an array with the same size as the input that has the execution result",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "success", ""},
                            {RPCResult::Type::ARR, "warnings", /*optional=*/true, "",
                            {
                                {RPCResult::Type::STR, "", ""},
                            }},
                            {RPCResult::Type::OBJ, "error", /*optional=*/true, "",
                            {
                                {RPCResult::Type::NUM, "code", "JSONRPC error code"},
                                {RPCResult::Type::STR, "message", "JSONRPC error message"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"internal\": true }, "
                                          "{ \"desc\": \"<my descriptor 2>\", \"label\": \"example 2\", \"timestamp\": 1455191480 }]'") +
                    HelpExampleCli("importdescriptors", "'[{ \"desc\": \"<my descriptor>\", \"timestamp\":1455191478, \"active\": true, \"range\": [0,100], \"label\": \"<my bech32 wallet>\" }]'")
                },
        [](const RPCMethod& self, const JSONRPCRequest& main_request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(main_request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    // Ensure that the wallet is not locked for the remainder of this RPC, as
    // the passphrase is used to top up the keypool.
    LOCK(pwallet->m_relock_mutex);

    const UniValue& requests = main_request.params[0];
    const int64_t minimum_timestamp = 1;
    int64_t now = 0;
    int64_t lowest_timestamp = 0;
    bool rescan = false;
    UniValue response(UniValue::VARR);
    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);

        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().time(lowest_timestamp).mtpTime(now)));

        // Get all timestamps and extract the lowest timestamp
        for (const UniValue& request : requests.getValues()) {
            // This throws an error if "timestamp" doesn't exist
            const int64_t timestamp = std::max(GetImportTimestamp(request, now), minimum_timestamp);
            const UniValue result = ProcessDescriptorImport(*pwallet, request, timestamp);
            response.push_back(result);

            if (lowest_timestamp > timestamp ) {
                lowest_timestamp = timestamp;
            }

            // If we know the chain tip, and at least one request was successful then allow rescan
            if (!rescan && result["success"].get_bool()) {
                rescan = true;
            }
        }
        pwallet->ConnectScriptPubKeyManNotifiers();
        pwallet->RefreshAllTXOs();
    }

    // Rescan the blockchain using the lowest timestamp
    if (rescan) {
        int64_t scanned_time = pwallet->RescanFromTime(lowest_timestamp, reserver, /*update=*/true);
        pwallet->ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_NO_BROADCAST, /*force=*/true);

        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
        }

        if (scanned_time > lowest_timestamp) {
            std::vector<UniValue> results = response.getValues();
            response.clear();
            response.setArray();

            // Compose the response
            for (unsigned int i = 0; i < requests.size(); ++i) {
                const UniValue& request = requests.getValues().at(i);

                // If the descriptor timestamp is within the successfully scanned
                // range, or if the import result already has an error set, let
                // the result stand unmodified. Otherwise replace the result
                // with an error message.
                if (scanned_time <= GetImportTimestamp(request, now) || results.at(i).exists("error")) {
                    response.push_back(results.at(i));
                } else {
                    std::string error_msg{strprintf("Rescan failed for descriptor with timestamp %d. There "
                            "was an error reading a block from time %d, which is after or within %d seconds "
                            "of key creation, and could contain transactions pertaining to the desc. As a "
                            "result, transactions and coins using this desc may not appear in the wallet.",
                            GetImportTimestamp(request, now), scanned_time - TIMESTAMP_WINDOW - 1, TIMESTAMP_WINDOW)};
                    if (pwallet->chain().havePruned()) {
                        error_msg += strprintf(" This error could be caused by pruning or data corruption "
                                "(see bitcoind log for details) and could be dealt with by downloading and "
                                "rescanning the relevant blocks (see -reindex option and rescanblockchain RPC).");
                    } else if (pwallet->chain().hasAssumedValidChain()) {
                        error_msg += strprintf(" This error is likely caused by an in-progress assumeutxo "
                                "background sync. Check logs or getchainstates RPC for assumeutxo background "
                                "sync progress and try again later.");
                    } else {
                        error_msg += strprintf(" This error could potentially caused by data corruption. If "
                                "the issue persists you may want to reindex (see -reindex option).");
                    }

                    UniValue result = UniValue(UniValue::VOBJ);
                    result.pushKV("success", UniValue(false));
                    result.pushKV("error", JSONRPCError(RPC_MISC_ERROR, error_msg));
                    response.push_back(std::move(result));
                }
            }
        }
    }

    return response;
},
    };
}

RPCMethod listdescriptors()
{
    return RPCMethod{
        "listdescriptors",
        "List all descriptors present in a wallet.\n",
        {
            {"private", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show private descriptors."}
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "wallet_name", "Name of wallet this operation was performed on"},
            {RPCResult::Type::ARR, "descriptors", "Array of descriptor objects (sorted by descriptor string representation)",
            {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "desc", "Descriptor string representation"},
                    {RPCResult::Type::NUM, "timestamp", "The creation time of the descriptor"},
                    {RPCResult::Type::BOOL, "active", "Whether this descriptor is currently used to generate new addresses"},
                    {RPCResult::Type::BOOL, "internal", /*optional=*/true, "True if this descriptor is used to generate change addresses. False if this descriptor is used to generate receiving addresses; defined only for active descriptors"},
                    {RPCResult::Type::ARR_FIXED, "range", /*optional=*/true, "Defined only for ranged descriptors", {
                        {RPCResult::Type::NUM, "", "Range start inclusive"},
                        {RPCResult::Type::NUM, "", "Range end inclusive"},
                    }},
                    {RPCResult::Type::NUM, "next", /*optional=*/true, "Same as next_index field. Kept for compatibility reason."},
                    {RPCResult::Type::NUM, "next_index", /*optional=*/true, "The next index to generate addresses from; defined only for ranged descriptors"},
                }},
            }}
        }},
        RPCExamples{
            HelpExampleCli("listdescriptors", "") + HelpExampleRpc("listdescriptors", "")
            + HelpExampleCli("listdescriptors", "true") + HelpExampleRpc("listdescriptors", "true")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    const bool priv = !request.params[0].isNull() && request.params[0].get_bool();
    if (wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && priv) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Can't get private descriptor string for watch-only wallets");
    }
    if (priv) {
        EnsureWalletIsUnlocked(*wallet);
    }

    LOCK(wallet->cs_wallet);

    const auto active_spk_mans = wallet->GetActiveScriptPubKeyMans();

    std::vector<WalletDescriptorInfo> wallet_descriptors;
    for (const auto& spk_man : wallet->GetAllScriptPubKeyMans()) {
        const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk_man) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unexpected ScriptPubKey manager type.");
        }
        LOCK(desc_spk_man->cs_desc_man);
        const auto& wallet_descriptor = desc_spk_man->GetWalletDescriptor();
        std::string descriptor;
        CHECK_NONFATAL(desc_spk_man->GetDescriptorString(descriptor, priv));
        const bool is_range = wallet_descriptor.descriptor->IsRange();
        wallet_descriptors.push_back({
            descriptor,
            wallet_descriptor.creation_time,
            active_spk_mans.contains(desc_spk_man),
            wallet->IsInternalScriptPubKeyMan(desc_spk_man),
            is_range ? std::optional(std::make_pair(wallet_descriptor.range_start, wallet_descriptor.range_end)) : std::nullopt,
            wallet_descriptor.next_index
        });
    }

    std::sort(wallet_descriptors.begin(), wallet_descriptors.end(), [](const auto& a, const auto& b) {
        return a.descriptor < b.descriptor;
    });

    UniValue descriptors(UniValue::VARR);
    for (const WalletDescriptorInfo& info : wallet_descriptors) {
        descriptors.push_back(DescriptorInfoToUniValue(info));
    }

    UniValue response(UniValue::VOBJ);
    response.pushKV("wallet_name", wallet->GetName());
    response.pushKV("descriptors", std::move(descriptors));

    return response;
},
    };
}

RPCMethod backupwallet()
{
    return RPCMethod{
        "backupwallet",
        "Safely copies the current wallet file to the specified destination, which can either be a directory or a path with a filename.\n",
                {
                    {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination directory or file"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return UniValue::VNULL;
},
    };
}


RPCMethod restorewallet()
{
    return RPCMethod{
        "restorewallet",
        "Restores and loads a wallet from backup.\n"
        "\nThe rescan is significantly faster if block filters are available"
        "\n(using startup option \"-blockfilterindex=1\").\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name that will be applied to the restored wallet"},
            {"backup_file", RPCArg::Type::STR, RPCArg::Optional::NO, "The backup file that will be used to restore the wallet."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if restored successfully."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to restoring and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("restorewallet", "\"testwallet\" \"home\\backups\\backup-file.bak\"")
            + HelpExampleRpc("restorewallet", "\"testwallet\" \"home\\backups\\backup-file.bak\"")
            + HelpExampleCliNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak\""}, {"load_on_startup", true}})
            + HelpExampleRpcNamed("restorewallet", {{"wallet_name", "testwallet"}, {"backup_file", "home\\backups\\backup-file.bak\""}, {"load_on_startup", true}})
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{

    WalletContext& context = EnsureWalletContext(request.context);

    auto backup_file = fs::u8path(request.params[1].get_str());

    std::string wallet_name = request.params[0].get_str();

    std::optional<bool> load_on_start = request.params[2].isNull() ? std::nullopt : std::optional<bool>(request.params[2].get_bool());

    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    const std::shared_ptr<CWallet> wallet = RestoreWallet(context, backup_file, wallet_name, load_on_start, status, error, warnings);

    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;

},
    };
}

RPCMethod encryptdescriptor()
{
    return RPCMethod{
        "encryptdescriptor",
        "Encrypt a descriptor string using the BIP-XXXX encrypted backup format.\n"
        "The encryption key is derived from the public keys in the descriptor.\n"
        "Returns the encrypted backup as a base64-encoded string, or writes raw binary to backupfile if provided.\n",
        {
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor string to encrypt (must include checksum)."},
            {"backupfile", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If provided, write the raw binary backup to this file instead of returning base64."},
        },
        {
            RPCResult{"backupfile is not set",
                RPCResult::Type::STR, "", "The encrypted backup as a base64 string"},
            RPCResult{"backupfile is set",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "filename", "The full path of the written backup file"},
                }},
        },
        RPCExamples{
            HelpExampleCli("encryptdescriptor", "\"wpkh([d34db33f/84h/0h/0h]tpub.../0/*)#checksum\"")
            + HelpExampleCli("encryptdescriptor", "\"wpkh([d34db33f/84h/0h/0h]tpub.../0/*)#checksum\" \"backup.bin\"")
            + HelpExampleRpc("encryptdescriptor", "\"wpkh([d34db33f/84h/0h/0h]tpub.../0/*)#checksum\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string descriptor = request.params[0].get_str();

    std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());

    // ExtractKeysFromDescriptor will sanity-check the descriptor, no need for duplicate check
    auto keys_and_paths = ExtractKeysFromDescriptor(descriptor);
    if (!keys_and_paths) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor: %s", util::ErrorString(keys_and_paths).original));
    }
    auto& [encryption_keys, derivation_paths] = *keys_and_paths;

    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);

    auto backup = CreateEncryptedBackup(encryption_keys, plaintext, content, derivation_paths);
    if (!backup) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to create encrypted backup: %s", util::ErrorString(backup).original));
    }

    if (!request.params[1].isNull()) {
        const std::string filename = request.params[1].get_str();
        fs::path out_path = fs::absolute(fs::PathFromString(filename));
        if (fs::exists(out_path)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("File %s already exists.", fs::PathToString(out_path)));
        }
        auto binary_backup = EncodeEncryptedBackup(*backup);
        if (!binary_backup) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Error encoding backup: %s", util::ErrorString(binary_backup).original));
        }
        std::ofstream out_file(out_path.std_path(), std::ios::binary);
        if (out_file.fail()) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Unable to open %s for writing", fs::PathToString(out_path)));
        }
        out_file.write(reinterpret_cast<const char*>(binary_backup->data()), binary_backup->size());
        if (out_file.fail()) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Error writing backup to %s", fs::PathToString(out_path)));
        }
        UniValue result(UniValue::VOBJ);
        result.pushKV("filename", fs::PathToString(out_path));
        return result;
    }

    auto base64_backup = EncodeEncryptedBackupBase64(*backup);
    if (!base64_backup) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Error encoding backup: %s", util::ErrorString(base64_backup).original));
    }

    return *base64_backup;
},
    };
}

/** Read an encrypted backup from either a base64 string parameter or a binary file. */
static util::Result<EncryptedBackup> ReadBackupFromRPCParam(const UniValue& backup_param, const UniValue& backupfile_param)
{
    if (!backupfile_param.isNull()) {
        const std::string& filename = backupfile_param.get_str();
        fs::path in_path = fs::absolute(fs::PathFromString(filename));
        std::ifstream in_file(in_path.std_path(), std::ios::binary);
        if (in_file.fail()) {
            return util::Error{Untranslated(strprintf("Unable to open %s for reading", fs::PathToString(in_path)))};
        }
        std::vector<uint8_t> binary_input((std::istreambuf_iterator<char>(in_file)),
                                          std::istreambuf_iterator<char>());
        auto res = DecodeEncryptedBackup(binary_input);
        if (!res) {
            // try to fallback to base64 decoding
            std::string str_input(binary_input.begin(), binary_input.end());
            auto b64_res = DecodeEncryptedBackupBase64(str_input);
            if (b64_res) return b64_res;
        }
        return res;
    }
    if (backup_param.isNull()) {
        return util::Error{Untranslated("Either \"backup\" or \"backupfile\" must be provided.")};
    }
    return DecodeEncryptedBackupBase64(backup_param.get_str());
}

/** Validate that params follow the (backup, xpub, backupfile) convention. */
static void ValidateBackupAndXpubParams(const UniValue& params)
{
    if (params[1].isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "An extended public key (xpub) must be provided");
    }
    const bool has_backup = !params[0].isNull() && !params[0].get_str().empty();
    const bool has_backupfile = !params[2].isNull() && !params[2].get_str().empty();
    if (has_backup == has_backupfile) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Pass either backup or backupfile, but not both");
    }
}

RPCMethod decryptdescriptor()
{
    return RPCMethod{
        "decryptdescriptor",
        "Decrypt a BIP-XXXX encrypted descriptor and return the descriptor string.\n"
        "The backup can be provided as a base64 string or read from a binary file via backupfile.\n"
        "No wallet is needed.\n",
        {
            {"backup", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The base64-encoded encrypted backup (omit if using backupfile)."},
            {"xpub", RPCArg::Type::STR, RPCArg::Optional::NO, "The extended public key (xpub/tpub) to decrypt with."},
            {"backupfile", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If provided, read the raw binary backup from this file instead of the backup parameter."},
        },
        RPCResult{RPCResult::Type::STR, "", "The decrypted descriptor string"},
        RPCExamples{
            HelpExampleCli("decryptdescriptor", "\"base64...\" \"tpub...\"")
            + HelpExampleCli("decryptdescriptor", "\"\" \"tpub...\" \"backup.bin\"")
            + HelpExampleRpc("decryptdescriptor", "\"base64...\", \"tpub...\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    ValidateBackupAndXpubParams(request.params);

    auto backup_result = ReadBackupFromRPCParam(request.params[0], request.params[2]);
    if (!backup_result) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to decode backup: %s", util::ErrorString(backup_result).original));
    }

    auto descriptor = DecryptDescriptorWithXpub(*backup_result, request.params[1].get_str());
    if (!descriptor) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(descriptor).original);
    }

    return *descriptor;
},
    };
}

RPCMethod importencrypteddescriptor()
{
    return RPCMethod{
        "importencrypteddescriptor",
        "Decrypt a BIP-XXXX encrypted backup and import the descriptor into the wallet.\n"
        "The backup can be provided as a base64 string or read from a binary file via backupfile.\n",
        {
            {"backup", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The base64-encoded encrypted backup (omit if using backupfile)."},
            {"xpub", RPCArg::Type::STR, RPCArg::Optional::NO, "The extended public key (xpub/tpub) to decrypt with."},
            {"backupfile", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If provided, read the raw binary backup from this file instead of the backup parameter."},
        },
        RPCResult{RPCResult::Type::STR, "", "The imported descriptor string"},
        RPCExamples{
            HelpExampleCli("importencrypteddescriptor", "\"base64...\" \"tpub...\"")
            + HelpExampleCli("importencrypteddescriptor", "\"\" \"tpub...\" \"backup.bin\"")
            + HelpExampleRpc("importencrypteddescriptor", "\"base64...\", \"tpub...\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    ValidateBackupAndXpubParams(request.params);

    // Decode and decrypt
    auto backup_result = ReadBackupFromRPCParam(request.params[0], request.params[2]);
    if (!backup_result) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to decode backup: %s", util::ErrorString(backup_result).original));
    }

    auto descriptor_result = DecryptDescriptorWithXpub(*backup_result, request.params[1].get_str());
    if (!descriptor_result) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(descriptor_result).original);
    }

    // Parse descriptor
    std::string descriptor(*descriptor_result);
    FlatSigningProvider keys;
    std::string error;
    auto parsed_descs = Parse(descriptor, keys, error, /*require_checksum=*/true);
    if (parsed_descs.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor in backup: %s", error));
    }

    LOCK(pwallet->cs_wallet);

    for (size_t j = 0; j < parsed_descs.size(); ++j) {
        auto& parsed_desc = parsed_descs[j];
        const bool is_range = parsed_desc->IsRange();
        int64_t range_start = 0;
        int64_t range_end = is_range ? pwallet->m_keypool_size : 0;

        WalletDescriptor w_desc(std::move(parsed_desc), /*creation_time=*/1, range_start, range_end, /*next_index=*/0);

        bool internal = (parsed_descs.size() == 2 && j == 1);
        auto spk_manager_res = pwallet->AddWalletDescriptor(w_desc, keys, /*label=*/"", internal);
        if (!spk_manager_res) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to import descriptor: %s", util::ErrorString(spk_manager_res).original));
        }
    }

    return UniValue(descriptor);
},
    };
}

} // namespace wallet
