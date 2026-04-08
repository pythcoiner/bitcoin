// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <core_io.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <merkleblock.h>
#include <node/types.h>
#include <chainparams.h>
#include <common/args.h>
#include <outputtype.h>
#include <rpc/util.h>
#include <wallet/context.h>
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
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <cstdint>
#include <fstream>
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

    struct WalletDescInfo {
        std::string descriptor;
        uint64_t creation_time;
        bool active;
        std::optional<bool> internal;
        std::optional<std::pair<int64_t,int64_t>> range;
        int64_t next_index;
    };

    std::vector<WalletDescInfo> wallet_descriptors;
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
    for (const WalletDescInfo& info : wallet_descriptors) {
        UniValue spk(UniValue::VOBJ);
        spk.pushKV("desc", info.descriptor);
        spk.pushKV("timestamp", info.creation_time);
        spk.pushKV("active", info.active);
        if (info.internal.has_value()) {
            spk.pushKV("internal", info.internal.value());
        }
        if (info.range.has_value()) {
            UniValue range(UniValue::VARR);
            range.push_back(info.range->first);
            range.push_back(info.range->second - 1);
            spk.pushKV("range", std::move(range));
            spk.pushKV("next", info.next_index);
            spk.pushKV("next_index", info.next_index);
        }
        descriptors.push_back(std::move(spk));
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
namespace {

//! Map Core's internal chain type string to the bip-wallet-backup spec value.
std::string ChainTypeToSpecNetwork(const std::string& chain_type)
{
    if (chain_type == "main") return "bitcoin";
    if (chain_type == "test") return "testnet3";
    if (chain_type == "testnet4") return "testnet4";
    if (chain_type == "signet") return "signet";
    if (chain_type == "regtest") return "regtest";
    return chain_type;
}

struct DescInfo {
    std::string descriptor;
    uint64_t creation_time{0};
    int64_t next_index{0};
    int64_t range_start{0};
    int64_t range_end{0};
    bool is_range{false};
    std::optional<OutputType> output_type;
    uint256 id;
};

DescInfo CollectDescInfo(DescriptorScriptPubKeyMan& spk_man)
{
    LOCK(spk_man.cs_desc_man);
    const auto& wd = spk_man.GetWalletDescriptor();
    DescInfo info;
    CHECK_NONFATAL(spk_man.GetDescriptorString(info.descriptor, /*priv=*/false));
    info.creation_time = wd.creation_time;
    info.next_index = wd.next_index;
    info.range_start = wd.range_start;
    info.range_end = wd.range_end;
    info.is_range = wd.descriptor->IsRange();
    info.output_type = wd.descriptor->GetOutputType();
    info.id = spk_man.GetID();
    return info;
}

UniValue BuildLabelsArray(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue labels(UniValue::VARR);
    wallet.ForEachAddrBookEntry([&](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) {
        if (is_change) return;
        if (label.empty()) return;
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("type", "addr");
        entry.pushKV("ref", EncodeDestination(dest));
        entry.pushKV("label", label);
        // Bitcoin Core extension: address purpose ("send"/"receive"). Not in BIP-329.
        if (purpose) entry.pushKV("purpose", PurposeToString(*purpose));
        labels.push_back(std::move(entry));
    });
    // Emit user-supplied transaction comments as BIP-329 type:"tx" records.
    for (const auto& [_pos, pwtx] : wallet.wtxOrdered) {
        const CWalletTx& wtx = *pwtx;
        auto it = wtx.mapValue.find("comment");
        if (it == wtx.mapValue.end() || it->second.empty()) continue;
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("type", "tx");
        entry.pushKV("ref", wtx.GetHash().GetHex());
        entry.pushKV("label", it->second);
        labels.push_back(std::move(entry));
    }
    return labels;
}

UniValue BuildTransactionsArray(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue txs(UniValue::VARR);
    for (const auto& [_pos, pwtx] : wallet.wtxOrdered) {
        const CWalletTx& wtx = *pwtx;
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", wtx.GetHash().GetHex());
        entry.pushKV("wtxid", wtx.GetWitnessHash().GetHex());
        entry.pushKV("hex", EncodeHexTx(*wtx.tx));
        entry.pushKV("time", wtx.GetTxTime());
        entry.pushKV("time_received", int64_t{wtx.nTimeReceived});
        if (auto* conf = wtx.state<TxStateConfirmed>()) {
            entry.pushKV("blockhash", conf->confirmed_block_hash.GetHex());
            entry.pushKV("blockheight", conf->confirmed_block_height);
            entry.pushKV("blockindex", conf->position_in_block);
        }
        entry.pushKV("abandoned", wtx.isAbandoned());
        txs.push_back(std::move(entry));
    }
    return txs;
}

UniValue BuildWalletFlagsArray(const CWallet& wallet)
{
    UniValue flags(UniValue::VARR);
    const uint64_t wallet_flags = wallet.GetWalletFlags();
    for (uint64_t i = 0; i < 64; ++i) {
        const uint64_t flag = uint64_t{1} << i;
        if (!(flag & wallet_flags)) continue;
        if (flag & KNOWN_WALLET_FLAGS) {
            flags.push_back(WALLET_FLAG_TO_STRING.at(WalletFlags{flag}));
        }
    }
    return flags;
}

//! Read the bitcoin.conf file and return its content with credential-bearing
//! settings stripped. Returns std::nullopt if no config file is in use.
std::optional<std::string> ReadSanitizedConfigFile()
{
    static const std::set<std::string> kSensitiveKeys{
        "rpcpassword",
        "rpcauth",
        "rpcuser",
        "torpassword",
        "tor",
        "onion",
        "i2psam",
        "proxy",
        "externalip",
    };

    const fs::path conf_path = gArgs.GetConfigFilePath();
    std::ifstream in{conf_path.std_path()};
    if (!in.is_open()) return std::nullopt;

    std::string out;
    std::string line;
    while (std::getline(in, line)) {
        // Find the key on this line, ignoring leading whitespace and section
        // headers ([main], [test], ...).
        std::string trimmed = line;
        size_t start = trimmed.find_first_not_of(" \t");
        bool sensitive = false;
        if (start != std::string::npos && trimmed[start] != '#' && trimmed[start] != '[') {
            const size_t eq = trimmed.find('=', start);
            if (eq != std::string::npos) {
                std::string key = trimmed.substr(start, eq - start);
                // Strip optional "section." prefix.
                if (const size_t dot = key.find('.'); dot != std::string::npos) {
                    key = key.substr(dot + 1);
                }
                // Trim trailing whitespace from the key.
                while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
                if (kSensitiveKeys.count(key)) sensitive = true;
            }
        }
        if (sensitive) {
            out += "# [redacted by exportwalletbackup]\n";
        } else {
            out += line;
            out += '\n';
        }
    }
    return out;
}

//! Build the accounts[] array. Pairs each external descriptor SPKM with the
//! matching internal SPKM of the same OutputType (when both exist), so a
//! single account exposes a receive descriptor + change descriptor.
UniValue BuildAccountsArray(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const auto active_spk_mans = wallet.GetActiveScriptPubKeyMans();

    struct Slot { DescriptorScriptPubKeyMan* recv{nullptr}; DescriptorScriptPubKeyMan* change{nullptr}; };
    std::map<OutputType, Slot> active_by_type;
    std::vector<DescriptorScriptPubKeyMan*> orphans; // inactive or untyped

    for (auto* spk_man : wallet.GetAllScriptPubKeyMans()) {
        auto* desc = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc) {
            throw JSONRPCError(RPC_WALLET_ERROR, "exportwalletbackup: only descriptor wallets are supported");
        }
        const bool is_active = active_spk_mans.contains(desc);
        std::optional<OutputType> ot;
        {
            LOCK(desc->cs_desc_man);
            ot = desc->GetWalletDescriptor().descriptor->GetOutputType();
        }
        const auto internal = wallet.IsInternalScriptPubKeyMan(desc);
        if (is_active && ot && internal.has_value()) {
            auto& slot = active_by_type[*ot];
            (internal.value() ? slot.change : slot.recv) = desc;
        } else {
            orphans.push_back(desc);
        }
    }

    UniValue accounts(UniValue::VARR);

    auto emit = [&](DescriptorScriptPubKeyMan* recv, DescriptorScriptPubKeyMan* change, bool active) {
        UniValue acc(UniValue::VOBJ);
        acc.pushKV("type", "bip_380");
        acc.pushKV("active", active);

        std::optional<DescInfo> recv_info;
        std::optional<DescInfo> change_info;
        if (recv) recv_info = CollectDescInfo(*recv);
        if (change) change_info = CollectDescInfo(*change);

        if (recv_info) {
            acc.pushKV("descriptor", recv_info->descriptor);
            acc.pushKV("descriptor_id", recv_info->id.GetHex());
            acc.pushKV("receive_index", recv_info->next_index);
            if (recv_info->is_range) {
                acc.pushKV("receive_range_start", recv_info->range_start);
                acc.pushKV("receive_range_end", recv_info->range_end);
            }
        }
        if (change_info) {
            acc.pushKV("change_descriptor", change_info->descriptor);
            acc.pushKV("change_descriptor_id", change_info->id.GetHex());
            acc.pushKV("change_index", change_info->next_index);
            if (change_info->is_range) {
                acc.pushKV("change_range_start", change_info->range_start);
                acc.pushKV("change_range_end", change_info->range_end);
            }
        }

        // Account-level timestamp = oldest creation_time across the paired descriptors,
        // so the import side can rescan from a safe lower bound.
        std::optional<uint64_t> ts;
        if (recv_info) ts = recv_info->creation_time;
        if (change_info) ts = ts ? std::min(*ts, change_info->creation_time) : change_info->creation_time;
        if (ts) {
            acc.pushKV("timestamp", static_cast<int64_t>(*ts));
            acc.pushKV("iso_8601_datetime", FormatISO8601DateTime(static_cast<int64_t>(*ts)));
            // Best-effort block_height: first block at-or-after the descriptor's
            // creation time. Lets an importer rescan from a tighter lower bound
            // than rescanning the whole chain.
            int height = 0;
            if (wallet.chain().findFirstBlockWithTimeAndHeight(static_cast<int64_t>(*ts), /*min_height=*/0, FoundBlock().height(height))) {
                // Step one block back as a safety margin against clock skew, so an
                // importer rescanning from `block_height` cannot miss a same-second tx.
                acc.pushKV("block_height", std::max(0, height - 1));
            }
        }

        // Output type — should match between receive and change in practice.
        std::optional<OutputType> ot = recv_info ? recv_info->output_type : change_info->output_type;
        if (ot) acc.pushKV("output_type", FormatOutputType(*ot));

        accounts.push_back(std::move(acc));
    };

    for (auto& [_ot, slot] : active_by_type) {
        emit(slot.recv, slot.change, /*active=*/true);
    }
    for (auto* desc : orphans) {
        emit(desc, nullptr, /*active=*/false);
    }
    return accounts;
}

UniValue BuildBackupJson(const CWallet& wallet, const std::string& chain_type) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue root(UniValue::VOBJ);
    root.pushKV("version", 1);
    root.pushKV("name", wallet.GetName());
    root.pushKV("network", ChainTypeToSpecNetwork(chain_type));
    // Last block the wallet has processed — useful for an importer to know the
    // safe rescan upper bound. Spec field at the account level; Core only
    // tracks it per-wallet, so we surface it at the root.
    if (wallet.GetLastBlockHeight() >= 0) {
        root.pushKV("last_height", wallet.GetLastBlockHeight());
    }
    // Bitcoin Core extension: wallet-level flags (e.g. avoid_reuse,
    // disable_private_keys, descriptor_wallet). Proposed for the spec.
    root.pushKV("wallet_flags", BuildWalletFlagsArray(wallet));
    // Bitcoin Core extension: bitcoin.conf content with credential-bearing
    // settings stripped (rpcpassword, rpcauth, tor passwords, ...).
    if (auto conf = ReadSanitizedConfigFile()) {
        root.pushKV("bitcoin_conf", *conf);
    }
    root.pushKV("accounts", BuildAccountsArray(wallet));
    root.pushKV("bip329_labels", BuildLabelsArray(wallet));
    root.pushKV("transactions", BuildTransactionsArray(wallet));

    return root;
}

} // namespace

RPCMethod exportwalletbackup()
{
    return RPCMethod{
        "exportwalletbackup",
        "Export a descriptor wallet's metadata as JSON conforming to the bip-wallet-backup format.\n"
        "Does NOT include private keys, mnemonics, or PSBTs.\n"
        "If a path is provided, the JSON is written to that file (which must not already exist) and the RPC returns null.\n"
        "Otherwise, the JSON object is returned directly.\n"
        "\nThis RPC emits some Bitcoin Core extension fields beyond the spec (output_type, change_descriptor, descriptor_id, address purpose) which we propose adding to the BIP.\n",
        {
            {"path", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If given, write the JSON backup to this file path."},
        },
        {
            RPCResult{"if path is omitted",
                RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", ""}}},
            RPCResult{"if path is provided",
                RPCResult::Type::NONE, "", ""},
        },
        RPCExamples{
            HelpExampleCli("exportwalletbackup", "")
            + HelpExampleCli("exportwalletbackup", "\"/tmp/backup.json\"")
            + HelpExampleRpc("exportwalletbackup", "")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (!pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "exportwalletbackup is only supported for descriptor wallets");
    }

    const std::string chain_type = Params().GetChainTypeString();

    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue backup;
    {
        LOCK(pwallet->cs_wallet);
        backup = BuildBackupJson(*pwallet, chain_type);
    }

    if (request.params[0].isNull()) {
        return backup;
    }

    fs::path filepath = fs::absolute(fs::u8path(request.params[0].get_str()));
    if (fs::exists(filepath)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, filepath.utf8string() + " already exists. If you are sure this is what you want, move it out of the way first");
    }
    std::ofstream file{filepath.std_path()};
    if (!file.is_open()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet backup file " + filepath.utf8string());
    }
    file << backup.write(/*prettyIndent=*/2);
    file.close();
    if (file.fail()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to write wallet backup to " + filepath.utf8string());
    }
    return UniValue::VNULL;
},
    };
}

namespace {

//! Load the backup JSON from either a filesystem path or an inline JSON object
//! string. A leading '{' is treated as inline JSON; anything else is a path.
UniValue LoadBackupSource(const std::string& source)
{
    std::string payload;
    size_t first_nonws = source.find_first_not_of(" \t\r\n");
    if (first_nonws != std::string::npos && source[first_nonws] == '{') {
        payload = source;
    } else {
        fs::path filepath = fs::absolute(fs::u8path(source));
        if (!fs::exists(filepath)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Backup file not found: " + filepath.utf8string());
        }
        std::ifstream in{filepath.std_path(), std::ios::binary};
        if (!in.is_open()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open backup file: " + filepath.utf8string());
        }
        std::stringstream ss;
        ss << in.rdbuf();
        payload = ss.str();
    }
    UniValue backup;
    if (!backup.read(payload)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Backup content is not valid JSON");
    }
    if (!backup.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Backup root must be a JSON object");
    }
    return backup;
}

//! Build a single ProcessDescriptorImport request UniValue for one side
//! (external or change) of an account, based on the exported fields.
UniValue BuildDescriptorRequest(const UniValue& account, bool internal, int64_t fallback_timestamp)
{
    const std::string desc_key = internal ? "change_descriptor" : "descriptor";
    const std::string index_key = internal ? "change_index" : "receive_index";
    const std::string range_start_key = internal ? "change_range_start" : "range_start";
    const std::string range_end_key = internal ? "change_range_end" : "range_end";
    // Back-compat: the exporter historically used `receive_range_*` for the
    // external side; accept both.
    const std::string alt_range_start_key = internal ? "change_range_start" : "receive_range_start";
    const std::string alt_range_end_key = internal ? "change_range_end" : "receive_range_end";

    UniValue req(UniValue::VOBJ);
    req.pushKV("desc", account[desc_key].get_str());
    req.pushKV("active", account.exists("active") ? account["active"].get_bool() : true);
    req.pushKV("internal", internal);

    int64_t ts = fallback_timestamp;
    if (account.exists("timestamp") && account["timestamp"].isNum()) {
        ts = account["timestamp"].getInt<int64_t>();
    }
    req.pushKV("timestamp", ts);

    // Range: prefer explicit fields, otherwise derive from next index.
    int64_t range_start = 0;
    int64_t range_end = 0;
    if (account.exists(range_start_key) || account.exists(alt_range_start_key)) {
        range_start = account.exists(range_start_key) ? account[range_start_key].getInt<int64_t>()
                                                      : account[alt_range_start_key].getInt<int64_t>();
    }
    if (account.exists(range_end_key) || account.exists(alt_range_end_key)) {
        range_end = account.exists(range_end_key) ? account[range_end_key].getInt<int64_t>()
                                                  : account[alt_range_end_key].getInt<int64_t>();
    }
    int64_t next_index = 0;
    if (account.exists(index_key) && account[index_key].isNum()) {
        next_index = account[index_key].getInt<int64_t>();
    }
    if (range_end <= 0) {
        // Spec minimum: cover at least up to next_index plus the default keypool lookahead.
        range_end = std::max<int64_t>(next_index, 0);
    }
    if (range_end < next_index) range_end = next_index;
    // ProcessDescriptorImport's ParseDescriptorRange takes a [begin, end] inclusive pair.
    UniValue range(UniValue::VARR);
    range.push_back(range_start);
    range.push_back(range_end);
    req.pushKV("range", std::move(range));
    if (next_index > range_start) {
        req.pushKV("next_index", next_index);
    }
    return req;
}

//! Inject one transaction from the backup's transactions[] entry into the
//! wallet, if its address already matches an imported descriptor. Returns true
//! on success (including "already present"), false if the entry was unusable.
bool InjectBackupTransaction(CWallet& wallet, const UniValue& entry, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!entry.exists("hex")) {
        err = "tx entry missing hex";
        return false;
    }
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, entry["hex"].get_str())) {
        err = "tx hex decode failed";
        return false;
    }
    CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));

    TxState state = TxStateInactive{};
    if (entry.exists("blockhash") && entry.exists("blockheight") && entry.exists("blockindex")) {
        const uint256 blockhash{ParseHashV(entry["blockhash"], "blockhash")};
        bool in_active_chain = false;
        int confirmed_height = -1;
        if (!wallet.chain().findBlock(blockhash, FoundBlock().inActiveChain(in_active_chain).height(confirmed_height)) || !in_active_chain) {
            err = "tx confirming block is not in the active chain";
            return false;
        }
        state = TxStateConfirmed{
            blockhash,
            entry["blockheight"].getInt<int>(),
            entry["blockindex"].getInt<int>(),
        };
    }
    if (!wallet.IsMine(*tx_ref)) {
        err = "tx does not belong to any imported descriptor";
        return false;
    }
    wallet.AddToWallet(std::move(tx_ref), state);
    return true;
}

} // namespace

RPCMethod importwalletbackup()
{
    return RPCMethod{
        "importwalletbackup",
        "Create a new wallet and import a bip-wallet-backup JSON into it.\n"
        "The destination wallet is always newly created and watch-only (no private keys).\n"
        "\nRescan modes:\n"
        "  \"auto\"  (default) - inject transactions[] directly, then rescan from last_height if present.\n"
        "  \"force\" - always rescan from the earliest account timestamp, ignoring transactions[] as authoritative.\n"
        "  \"none\"  - do not rescan. Only descriptors, labels, and transactions[] are restored.\n",
        {
            {"source", RPCArg::Type::STR, RPCArg::Optional::NO, "Either a filesystem path to a JSON file, or the JSON object itself as a string."},
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "Name to give the newly-created wallet. Must not already exist."},
            {"rescan", RPCArg::Type::STR, RPCArg::Default{"auto"}, "Rescan strategy: \"auto\", \"force\", or \"none\"."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The new wallet's name."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "", {{RPCResult::Type::STR, "", ""}}},
            }
        },
        RPCExamples{
            HelpExampleCli("importwalletbackup", "\"/tmp/backup.json\" \"restored\"")
            + HelpExampleRpc("importwalletbackup", "\"/tmp/backup.json\", \"restored\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);

    // 1. Parse + validate the backup JSON up-front so we never create a wallet
    // for a malformed backup.
    UniValue backup = LoadBackupSource(request.params[0].get_str());

    if (backup.exists("version") && backup["version"].isNum() && backup["version"].getInt<int>() != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unsupported backup version %d (expected 1)", backup["version"].getInt<int>()));
    }
    if (backup.exists("network") && backup["network"].isStr()) {
        const std::string expected = ChainTypeToSpecNetwork(Params().GetChainTypeString());
        if (backup["network"].get_str() != expected) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Backup network \"%s\" does not match current network \"%s\"", backup["network"].get_str(), expected));
        }
    }
    if (!backup.exists("accounts") || !backup["accounts"].isArray() || backup["accounts"].empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Backup has no accounts to import");
    }

    // 2. Parse RPC args.
    const std::string wallet_name = request.params[1].get_str();
    std::string rescan_mode = "auto";
    if (!request.params[2].isNull()) {
        rescan_mode = request.params[2].get_str();
        if (rescan_mode != "auto" && rescan_mode != "force" && rescan_mode != "none") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "rescan must be one of \"auto\", \"force\", \"none\"");
        }
    }
    std::optional<bool> load_on_start = request.params[3].isNull() ? std::nullopt : std::optional<bool>(request.params[3].get_bool());

    // 3. Determine earliest timestamp across accounts (rescan lower bound).
    int64_t earliest_ts = std::numeric_limits<int64_t>::max();
    for (const UniValue& acc : backup["accounts"].getValues()) {
        if (acc.exists("timestamp") && acc["timestamp"].isNum()) {
            earliest_ts = std::min(earliest_ts, acc["timestamp"].getInt<int64_t>());
        }
    }
    if (earliest_ts == std::numeric_limits<int64_t>::max()) earliest_ts = 1;

    // 4. Create the destination wallet (watch-only, descriptor). The pruned
    // guard is handled post-rescan by RescanFromTime, which reports a clear
    // error covering both pruning and assumeutxo cases — matching the
    // importdescriptors behavior.
    DatabaseOptions options;
    DatabaseStatus status;
    ReadDatabaseArgs(*context.args, options);
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET;
    bilingual_str err;
    std::vector<bilingual_str> warnings;
    const std::shared_ptr<CWallet> pwallet = CreateWallet(context, wallet_name, load_on_start, options, status, err, warnings);
    HandleWalletError(pwallet, status, err);

    UniValue per_account_results(UniValue::VARR);

    // 6. Import descriptors via the existing ProcessDescriptorImport helper.
    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/false)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }
    {
        LOCK(pwallet->cs_wallet);
        int64_t now = 0;
        CHECK_NONFATAL(pwallet->chain().findBlock(pwallet->GetLastBlockHash(), FoundBlock().mtpTime(now)));

        for (const UniValue& acc : backup["accounts"].getValues()) {
            if (!acc.exists("descriptor")) {
                per_account_results.push_back("account skipped: missing \"descriptor\"");
                continue;
            }
            UniValue recv_req = BuildDescriptorRequest(acc, /*internal=*/false, now);
            int64_t ts = std::max<int64_t>(1, GetImportTimestamp(recv_req, now));
            per_account_results.push_back(ProcessDescriptorImport(*pwallet, recv_req, ts));
            if (acc.exists("change_descriptor")) {
                UniValue change_req = BuildDescriptorRequest(acc, /*internal=*/true, now);
                int64_t ts2 = std::max<int64_t>(1, GetImportTimestamp(change_req, now));
                per_account_results.push_back(ProcessDescriptorImport(*pwallet, change_req, ts2));
            }
        }
        pwallet->ConnectScriptPubKeyManNotifiers();
        pwallet->RefreshAllTXOs();

        // 7. Inject transactions[] before any rescan so the rescan only has to
        // cover the gap between the backup and the current tip.
        int injected = 0;
        int skipped = 0;
        if (backup.exists("transactions") && backup["transactions"].isArray()) {
            for (const UniValue& entry : backup["transactions"].getValues()) {
                std::string tx_err;
                if (InjectBackupTransaction(*pwallet, entry, tx_err)) {
                    ++injected;
                } else {
                    ++skipped;
                }
            }
        }
        if (injected > 0) warnings.emplace_back(Untranslated(strprintf("Injected %d transaction(s) from backup", injected)));
        if (skipped > 0) warnings.emplace_back(Untranslated(strprintf("Skipped %d transaction(s) from backup", skipped)));

        // 8. Apply BIP-329 labels.
        if (backup.exists("bip329_labels") && backup["bip329_labels"].isArray()) {
            int label_addr = 0;
            int label_tx = 0;
            int label_skipped = 0;
            for (const UniValue& entry : backup["bip329_labels"].getValues()) {
                if (!entry.exists("type") || !entry.exists("ref") || !entry.exists("label")) {
                    ++label_skipped;
                    continue;
                }
                const std::string type = entry["type"].get_str();
                const std::string ref = entry["ref"].get_str();
                const std::string label = entry["label"].get_str();
                if (type == "addr") {
                    CTxDestination dest = DecodeDestination(ref);
                    if (!IsValidDestination(dest)) {
                        ++label_skipped;
                        continue;
                    }
                    std::optional<AddressPurpose> purpose;
                    if (entry.exists("purpose") && entry["purpose"].isStr()) {
                        purpose = PurposeFromString(entry["purpose"].get_str());
                    }
                    pwallet->SetAddressBook(dest, label, purpose);
                    ++label_addr;
                } else if (type == "tx") {
                    Txid txid{Txid::FromUint256(ParseHashV(UniValue{ref}, "ref"))};
                    if (pwallet->mapWallet.count(txid) == 0) {
                        ++label_skipped;
                        continue;
                    }
                    CTransactionRef tx_ref = pwallet->mapWallet.at(txid).tx;
                    pwallet->AddToWallet(tx_ref, pwallet->mapWallet.at(txid).m_state,
                        [&label](CWalletTx& wtx, bool /*new_tx*/) {
                            wtx.mapValue["comment"] = label;
                            return true;
                        });
                    ++label_tx;
                } else {
                    ++label_skipped;
                }
            }
            if (label_addr > 0) warnings.emplace_back(Untranslated(strprintf("Applied %d address label(s)", label_addr)));
            if (label_tx > 0) warnings.emplace_back(Untranslated(strprintf("Applied %d tx label(s)", label_tx)));
            if (label_skipped > 0) warnings.emplace_back(Untranslated(strprintf("Skipped %d label entry(ies)", label_skipped)));
        }
    }

    // 9. Rescan, driven by the user's mode.
    if (rescan_mode != "none") {
        int64_t scan_from = earliest_ts;
        if (rescan_mode == "auto" && backup.exists("last_height") && backup["last_height"].isNum()) {
            const int last_height = backup["last_height"].getInt<int>();
            int64_t last_height_time = 0;
            {
                LOCK(pwallet->cs_wallet);
                if (pwallet->chain().findAncestorByHeight(pwallet->GetLastBlockHash(), last_height, FoundBlock().time(last_height_time))) {
                    scan_from = std::max(scan_from, last_height_time);
                }
            }
        }
        const int64_t scanned_time = pwallet->RescanFromTime(scan_from, reserver, /*update=*/true);
        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
        }
        if (scanned_time > scan_from) {
            std::string msg = strprintf("Rescan started from time %d instead of %d", scanned_time, scan_from);
            if (pwallet->chain().havePruned()) {
                msg += " (node is pruned; some history may be missing — re-index with -reindex to recover)";
            } else if (pwallet->chain().hasAssumedValidChain()) {
                msg += " (assumeutxo background sync in progress; retry later)";
            }
            warnings.emplace_back(Untranslated(msg));
        }
        pwallet->ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_NO_BROADCAST, /*force=*/true);
    } else {
        warnings.emplace_back(Untranslated("rescan=\"none\": historical transactions not covered by transactions[] will be missing"));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", pwallet->GetName());
    // Surface per-account import errors as warnings so the caller sees them.
    for (const UniValue& r : per_account_results.getValues()) {
        if (r.isObject() && r.exists("success") && !r["success"].get_bool() && r.exists("error")) {
            warnings.emplace_back(Untranslated(r["error"]["message"].get_str()));
        }
    }
    PushWarnings(warnings, obj);
    return obj;
},
    };
}

} // namespace wallet
