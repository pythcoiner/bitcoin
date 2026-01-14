// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <test/data/bip_encrypted_backup_derivation_path.json.h>
#include <test/data/bip_encrypted_backup_encryption_secret.json.h>
#include <test/data/bip_encrypted_backup_individual_secrets.json.h>
#include <test/data/bip_encrypted_backup_keys_types.json.h>

#include <base58.h>
#include <key_io.h>
#include <random.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

namespace wallet {

// Use RegTest chain type so tpub keys (testnet prefixes) can be parsed
struct EncryptedBackupTestingSetup : public BasicTestingSetup {
    EncryptedBackupTestingSetup() : BasicTestingSetup(ChainType::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(encrypted_backup_tests, EncryptedBackupTestingSetup)

BOOST_AUTO_TEST_CASE(key_normalization_test)
{
    // Test key normalization using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_keys_types);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        std::string key_str = vec["key"].get_str();
        std::string expected_hex = vec["expected"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse the expected x-only key
        auto expected_bytes = ParseHex(expected_hex);
        BOOST_REQUIRE_EQUAL(expected_bytes.size(), 32u);
        uint256 expected;
        std::memcpy(expected.data(), expected_bytes.data(), 32);

        // Determine key type and normalize
        uint256 result;

        if (key_str.size() == 64) {
            // X-only public key (32 bytes hex = 64 chars)
            auto key_bytes = ParseHex(key_str);
            BOOST_REQUIRE_EQUAL(key_bytes.size(), 32u);
            std::memcpy(result.data(), key_bytes.data(), 32);
        } else if (key_str.size() == 66 && (key_str[0] == '0' && (key_str[1] == '2' || key_str[1] == '3'))) {
            // Compressed public key
            auto key_bytes = ParseHex(key_str);
            BOOST_REQUIRE_EQUAL(key_bytes.size(), 33u);
            CPubKey pubkey(key_bytes.begin(), key_bytes.end());
            result = NormalizeToXOnly(pubkey);
        } else if (key_str.size() == 130 && key_str.starts_with("04")) {
            // Uncompressed public key
            auto key_bytes = ParseHex(key_str);
            BOOST_REQUIRE_EQUAL(key_bytes.size(), 65u);
            CPubKey pubkey(key_bytes.begin(), key_bytes.end());
            result = NormalizeToXOnly(pubkey);
        } else if (key_str.find("pub") != std::string::npos || key_str[0] == '[') {
            // Extended public key (xpub/tpub) potentially with origin info
            // For these test vectors, we're testing key extraction, not descriptor parsing.
            // We strip the derivation path suffix and extract just the xpub/tpub key.
            std::string xpub_only = key_str;

            // Remove origin prefix if present: [fingerprint/path]
            if (xpub_only[0] == '[') {
                size_t close = xpub_only.find(']');
                if (close != std::string::npos) {
                    xpub_only = xpub_only.substr(close + 1);
                }
            }

            // Remove derivation suffix if present: /<0;1>/* or /0/* etc
            size_t slash = xpub_only.find('/');
            if (slash != std::string::npos) {
                xpub_only = xpub_only.substr(0, slash);
            }

            // Parse the extended public key (uses RegTest chain so tpub prefix works)
            CExtPubKey ext_pubkey = DecodeExtPubKey(xpub_only);
            if (ext_pubkey.pubkey.IsValid()) {
                result = NormalizeToXOnly(ext_pubkey.pubkey);
            } else {
                // Fallback to raw base58 decoding for xpub (mainnet) keys
                std::vector<unsigned char> decoded_data;
                if (!DecodeBase58Check(xpub_only, decoded_data, 78)) {
                    BOOST_FAIL("Failed to decode xpub base58: " + xpub_only);
                }
                BOOST_REQUIRE_EQUAL(decoded_data.size(), 78u);
                CPubKey pubkey;
                pubkey.Set(decoded_data.begin() + 45, decoded_data.end());
                BOOST_REQUIRE_MESSAGE(pubkey.IsValid(), "Invalid pubkey in xpub");
                result = NormalizeToXOnly(pubkey);
            }
        } else {
            BOOST_FAIL("Unrecognized key format: " + key_str);
        }

        BOOST_CHECK_MESSAGE(result == expected,
            description << ": expected " << expected_hex << " got " << HexStr(result));
    }
}

BOOST_AUTO_TEST_CASE(secret_derivation_test)
{
    // Test secret derivation using BIP test vectors. Keys in the vectors are
    // 33-byte compressed pubkeys; normalize to 32-byte x-only before sorting.
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_encryption_secret);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        const UniValue& keys_arr = vec["keys"];

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse and normalize keys (compressed -> x-only).
        std::vector<uint256> keys;
        for (size_t j = 0; j < keys_arr.size(); ++j) {
            auto key_bytes = ParseHex(keys_arr[j].get_str());
            uint256 key;
            if (key_bytes.size() == 33) {
                std::memcpy(key.data(), key_bytes.data() + 1, 32);
            } else if (key_bytes.size() == 32) {
                std::memcpy(key.data(), key_bytes.data(), 32);
            } else {
                BOOST_FAIL("Unexpected key size in vector");
            }
            keys.push_back(key);
        }

        // Sort + dedupe (per spec: sorted lexicographically).
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());

        uint256 decryption_secret = ComputeDecryptionSecret(keys);
        auto individual_secrets = ComputeAllIndividualSecrets(decryption_secret, keys);

        // Compare decryption_secret to expected.
        auto expected_bytes = ParseHex(vec["decryption_secret"].get_str());
        BOOST_REQUIRE_EQUAL(expected_bytes.size(), 32u);
        uint256 expected;
        std::memcpy(expected.data(), expected_bytes.data(), 32);
        BOOST_CHECK_MESSAGE(decryption_secret == expected,
            description << ": decryption_secret mismatch, got " << HexStr(decryption_secret));

        // Compare individual_secrets to expected (order matches sorted keys).
        const UniValue& expected_ind = vec["individual_secrets"];
        BOOST_REQUIRE_EQUAL(expected_ind.size(), individual_secrets.size());
        for (size_t j = 0; j < individual_secrets.size(); ++j) {
            auto exp_bytes = ParseHex(expected_ind[j].get_str());
            BOOST_REQUIRE_EQUAL(exp_bytes.size(), 32u);
            uint256 exp_ci;
            std::memcpy(exp_ci.data(), exp_bytes.data(), 32);
            BOOST_CHECK_MESSAGE(individual_secrets[j] == exp_ci,
                description << ": individual_secrets[" << j << "] mismatch, got "
                << HexStr(individual_secrets[j]));
        }
    }
}

BOOST_AUTO_TEST_CASE(nums_point_test)
{
    // Verify NUMS point detection
    auto nums_bytes = ParseHex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
    uint256 nums_key;
    std::memcpy(nums_key.data(), nums_bytes.data(), 32);

    BOOST_CHECK(IsNUMSPoint(nums_key));

    // Random key should not be NUMS
    uint256 random_key;
    GetStrongRandBytes(random_key);
    BOOST_CHECK(!IsNUMSPoint(random_key));
}

BOOST_AUTO_TEST_CASE(derivation_path_encoding_test)
{
    // Test derivation path encoding using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_derivation_path);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        const UniValue& paths_arr = vec["paths"];

        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse paths
        std::vector<DerivationPath> paths;
        bool parse_failed = false;
        for (size_t j = 0; j < paths_arr.size(); ++j) {
            auto path_result = ParseDerivationPath(paths_arr[j].get_str());
            if (!path_result) {
                parse_failed = true;
                break;
            }
            paths.push_back(*path_result);
        }

        // Check if this test vector should fail
        if (vec["expected"].isNull()) {
            if (!parse_failed) {
                auto encoded_result = EncodeDerivationPaths(paths);
                BOOST_CHECK_MESSAGE(!encoded_result,
                    description << ": expected failure but got success");
            }
            continue;
        }

        BOOST_REQUIRE_MESSAGE(!parse_failed, description << ": unexpected parse failure");
        std::string expected_hex = vec["expected"].get_str();

        // Encode
        auto encoded_result = EncodeDerivationPaths(paths);
        BOOST_REQUIRE_MESSAGE(encoded_result, util::ErrorString(encoded_result).original);

        std::string result_hex = HexStr(*encoded_result);
        BOOST_CHECK_MESSAGE(result_hex == expected_hex,
            description << ": expected " << expected_hex << " got " << result_hex);

        // Test round-trip decode
        auto decoded_result = DecodeDerivationPaths(*encoded_result);
        BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);
        BOOST_CHECK_EQUAL(decoded_result->first.size(), paths.size());
        BOOST_CHECK_EQUAL(decoded_result->second, encoded_result->size());
    }
}

// ---------- Derivation path edge cases ----------

BOOST_AUTO_TEST_CASE(derivation_path_parse_corrupt_test)
{
    // child count = 1 but 0/1/2/3 trailing bytes => truncated (need 4)
    BOOST_CHECK(!DecodeDerivationPaths(std::vector<uint8_t>{0x01, 0x01, 0x00}));
    BOOST_CHECK(!DecodeDerivationPaths(std::vector<uint8_t>{0x01, 0x01, 0x00, 0x00}));
    BOOST_CHECK(!DecodeDerivationPaths(std::vector<uint8_t>{0x01, 0x01, 0x00, 0x00, 0x00}));
    // child count = 0 is invalid
    BOOST_CHECK(!DecodeDerivationPaths(std::vector<uint8_t>{0x01, 0x00}));
    // single valid path m/1
    auto ok = DecodeDerivationPaths(std::vector<uint8_t>{0x01, 0x01, 0x00, 0x00, 0x00, 0x01});
    BOOST_REQUIRE(ok);
    BOOST_CHECK_EQUAL(ok->first.size(), 1u);
}

BOOST_AUTO_TEST_CASE(derivation_path_empty_test)
{
    auto bytes = EncodeDerivationPaths({});
    BOOST_REQUIRE(bytes);
    BOOST_CHECK_EQUAL(HexStr(*bytes), "00");
    auto decoded = DecodeDerivationPaths(*bytes);
    BOOST_REQUIRE(decoded);
    BOOST_CHECK(decoded->first.empty());
}

BOOST_AUTO_TEST_CASE(derivation_path_too_many_test)
{
    std::vector<DerivationPath> paths;
    DerivationPath p{0, 1, 2, 3};
    for (size_t i = 0; i < 256; ++i) {
        DerivationPath tmp = p;
        tmp[0] = static_cast<uint32_t>(i);
        paths.push_back(tmp);
    }
    BOOST_CHECK(!EncodeDerivationPaths(paths));
}

BOOST_AUTO_TEST_CASE(derivation_path_too_long_test)
{
    DerivationPath path(256, 0u);
    BOOST_CHECK(!EncodeDerivationPaths({path}));
}

BOOST_AUTO_TEST_CASE(derivation_path_decode_dedup_test)
{
    // Hand-craft a byte stream with two identical paths; decoder must collapse.
    std::vector<uint8_t> bytes{0x02,
        0x01, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x01};
    auto decoded = DecodeDerivationPaths(bytes);
    BOOST_REQUIRE(decoded);
    BOOST_CHECK_EQUAL(decoded->first.size(), 1u);
}

BOOST_AUTO_TEST_CASE(derivation_path_decode_sorted_test)
{
    // Encode two paths in unsorted order, decode must return them sorted.
    auto bytes = EncodeDerivationPaths({
        DerivationPath{0x80000054u, 0x80000000u, 0x80000000u, 0x80000002u},
        DerivationPath{0u, 0x80000001u, 2u, 0x80000003u},
    });
    BOOST_REQUIRE(bytes);
    auto decoded = DecodeDerivationPaths(*bytes);
    BOOST_REQUIRE(decoded);
    BOOST_REQUIRE_EQUAL(decoded->first.size(), 2u);
    BOOST_CHECK_EQUAL(decoded->first[0][0], 0u);
    BOOST_CHECK_EQUAL(decoded->first[1][0], 0x80000054u);
}

BOOST_AUTO_TEST_CASE(individual_secrets_encoding_test)
{
    // Test individual secrets encoding using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_individual_secrets);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        const UniValue& secrets_arr = vec["secrets"];

        // Parse secrets
        std::vector<uint256> secrets;
        for (size_t j = 0; j < secrets_arr.size(); ++j) {
            auto secret_bytes = ParseHex(secrets_arr[j].get_str());
            if (secret_bytes.size() == 32) {
                uint256 secret;
                std::memcpy(secret.data(), secret_bytes.data(), 32);
                secrets.push_back(secret);
            }
        }

        // Check if this should fail
        if (vec["expected"].isNull()) {
            auto encoded_result = EncodeIndividualSecrets(secrets);
            BOOST_CHECK_MESSAGE(!encoded_result,
                description << ": expected failure but got success");
            continue;
        }

        std::string expected_hex = vec["expected"].get_str();

        // Encode
        auto encoded_result = EncodeIndividualSecrets(secrets);
        BOOST_REQUIRE_MESSAGE(encoded_result, util::ErrorString(encoded_result).original);

        std::string result_hex = HexStr(*encoded_result);
        BOOST_CHECK_MESSAGE(result_hex == expected_hex,
            description << ": expected " << expected_hex << " got " << result_hex);

        // Test round-trip decode
        auto decoded_result = DecodeIndividualSecrets(*encoded_result);
        BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);
        BOOST_CHECK_EQUAL(decoded_result->first.size(), secrets.size());
        BOOST_CHECK_EQUAL(decoded_result->second, encoded_result->size());
    }
}

// ---------- Individual secrets edge cases ----------

BOOST_AUTO_TEST_CASE(individual_secrets_parse_empty_test)
{
    BOOST_CHECK(!DecodeIndividualSecrets(std::vector<uint8_t>{}));
    BOOST_CHECK(!DecodeIndividualSecrets(std::vector<uint8_t>{0x00}));
}

BOOST_AUTO_TEST_CASE(individual_secrets_encode_empty_test)
{
    BOOST_CHECK(!EncodeIndividualSecrets({}));
}

BOOST_AUTO_TEST_CASE(individual_secrets_too_many_test)
{
    std::vector<uint256> secrets;
    for (size_t i = 0; i < 256; ++i) {
        uint256 s;
        GetStrongRandBytes(s);
        secrets.push_back(s);
    }
    BOOST_CHECK(!EncodeIndividualSecrets(secrets));
}

BOOST_AUTO_TEST_CASE(individual_secrets_encode_dedup_byte_test)
{
    // Two identical secrets collapse to one in the encoding.
    uint256 zero;
    std::memset(zero.data(), 0, 32);
    auto bytes = EncodeIndividualSecrets({zero, zero});
    BOOST_REQUIRE(bytes);
    std::string expected = "01" + std::string(64, '0');
    BOOST_CHECK_EQUAL(HexStr(*bytes), expected);
}

BOOST_AUTO_TEST_CASE(individual_secrets_decode_dedup_test)
{
    // Byte stream with count=2 and identical payloads; decoder collapses.
    std::vector<uint8_t> bytes{0x02};
    bytes.resize(1 + 2 * 32, 0x00);
    auto decoded = DecodeIndividualSecrets(bytes);
    BOOST_REQUIRE(decoded);
    BOOST_CHECK_EQUAL(decoded->first.size(), 1u);
    BOOST_CHECK_EQUAL(decoded->second, 1 + 2 * 32);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
