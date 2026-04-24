// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <test/data/bip_encrypted_backup_chacha20poly1305_encryption.json.h>
#include <test/data/bip_encrypted_backup_content_type.json.h>
#include <test/data/bip_encrypted_backup_derivation_path.json.h>
#include <test/data/bip_encrypted_backup_encrypted_backup.json.h>
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

BOOST_AUTO_TEST_CASE(content_type_encoding_test)
{
    // Test content type encoding using BIP test vectors
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_content_type);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        bool valid = vec["valid"].get_bool();
        std::string content_hex = vec["content"].get_str();

        BOOST_TEST_MESSAGE("Testing: " << description);

        auto content_bytes = ParseHex(content_hex);

        // Try to decode
        auto decoded_result = DecodeContent(content_bytes);

        if (!valid) {
            BOOST_CHECK_MESSAGE(!decoded_result,
                description << ": expected decode failure but got success");
        } else {
            BOOST_REQUIRE_MESSAGE(decoded_result,
                description << ": expected decode success but got: " <<
                (decoded_result ? "" : util::ErrorString(decoded_result).original));

            auto [content, bytes_consumed] = *decoded_result;

            if (content.type == ContentType::BIP_NUMBER ||
                content.type == ContentType::VENDOR_SPECIFIC) {
                auto reencoded = EncodeContent(content);
                BOOST_REQUIRE_MESSAGE(reencoded, util::ErrorString(reencoded).original);
                BOOST_CHECK_MESSAGE(HexStr(*reencoded) == content_hex,
                    description << ": re-encoded " << HexStr(*reencoded)
                    << " != input " << content_hex);
            }
        }
    }
}

// ---------- Content type edge cases ----------

BOOST_AUTO_TEST_CASE(content_parse_empty_test)
{
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{}));
}

BOOST_AUTO_TEST_CASE(content_parse_reserved_test)
{
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0x00}));
}

BOOST_AUTO_TEST_CASE(content_parse_bip_insufficient_test)
{
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0x01}));
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0x01, 0x01}));
}

BOOST_AUTO_TEST_CASE(content_parse_vendor_insufficient_test)
{
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0x02, 0x03, 0xAA, 0xBB}));
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0x02, 0x05, 0xAA, 0xBB, 0xCC}));
}

BOOST_AUTO_TEST_CASE(content_parse_upgrade_stop_test)
{
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0xFF}));
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0xFF, 0xAA}));
    BOOST_CHECK(!DecodeContent(std::vector<uint8_t>{0x80, 0x00}));
}

BOOST_AUTO_TEST_CASE(content_parse_unknown_skip_test)
{
    auto decoded = DecodeContent(std::vector<uint8_t>{0x05, 0x02, 0xAA, 0xBB});
    BOOST_REQUIRE(decoded);
    BOOST_CHECK_EQUAL(decoded->second, 4u);
}

BOOST_AUTO_TEST_CASE(content_serialize_known_test)
{
    auto enc = [](uint16_t n) {
        EncryptedBackupContent c;
        c.type = ContentType::BIP_NUMBER;
        c.bip_number = n;
        auto r = EncodeContent(c);
        BOOST_REQUIRE(r);
        return HexStr(*r);
    };
    BOOST_CHECK_EQUAL(enc(BIP_DESCRIPTORS), "01017c");
    BOOST_CHECK_EQUAL(enc(BIP_WALLET_POLICIES), "010184");
    BOOST_CHECK_EQUAL(enc(BIP_LABELS), "010149");
}

BOOST_AUTO_TEST_CASE(chacha20poly1305_roundtrip_test)
{
    // Test basic encryption/decryption roundtrip
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    uint256 secret;
    GetStrongRandBytes(secret);

    std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce;
    GetStrongRandBytes(nonce);

    // Encrypt
    auto ciphertext = EncryptChaCha20Poly1305(plaintext, secret, nonce);
    BOOST_CHECK_EQUAL(ciphertext.size(), plaintext.size() + AEADChaCha20Poly1305::EXPANSION);

    // Decrypt with correct key
    auto decrypted = DecryptChaCha20Poly1305(ciphertext, secret, nonce);
    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK(decrypted.value() == plaintext);

    // Decrypt with wrong key should fail
    uint256 wrong_secret;
    GetStrongRandBytes(wrong_secret);
    auto decrypted_wrong = DecryptChaCha20Poly1305(ciphertext, wrong_secret, nonce);
    BOOST_CHECK(!decrypted_wrong.has_value());
}

BOOST_AUTO_TEST_CASE(chacha20poly1305_vector_test)
{
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_chacha20poly1305_encryption);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        BOOST_TEST_MESSAGE("Testing: " << description);

        auto nonce_bytes = ParseHex(vec["nonce"].get_str());
        BOOST_REQUIRE_EQUAL(nonce_bytes.size(), AEADChaCha20Poly1305::NONCE_SIZE);
        std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce;
        std::memcpy(nonce.data(), nonce_bytes.data(), nonce.size());

        auto secret_bytes = ParseHex(vec["secret"].get_str());
        BOOST_REQUIRE_EQUAL(secret_bytes.size(), 32u);
        uint256 secret;
        std::memcpy(secret.data(), secret_bytes.data(), 32);

        auto plaintext = ParseHex(vec["plaintext"].get_str());

        // Vectors with null ciphertext represent inputs the spec rejects (e.g.
        // empty plaintext). The low-level EncryptChaCha20Poly1305 doesn't
        // enforce that rule; it lives at the CreateEncryptedBackup* layer, so
        // drive those cases through the high-level helper and assert failure.
        if (vec["ciphertext"].isNull()) {
            auto [dummy_keys, dummy_paths] = *ExtractKeysFromDescriptor("wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)");
            auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
            auto result = CreateEncryptedBackupWithNonce(dummy_keys, plaintext, content, dummy_paths, nonce);
            BOOST_CHECK_MESSAGE(!result,
                description << ": CreateEncryptedBackupWithNonce must reject this input");
            continue;
        }

        auto ciphertext = EncryptChaCha20Poly1305(plaintext, secret, nonce);
        std::string expected_hex = vec["ciphertext"].get_str();
        BOOST_CHECK_MESSAGE(HexStr(ciphertext) == expected_hex,
            description << ": ciphertext mismatch, got " << HexStr(ciphertext));

        auto decrypted = DecryptChaCha20Poly1305(ciphertext, secret, nonce);
        BOOST_REQUIRE(decrypted.has_value());
        BOOST_CHECK(*decrypted == plaintext);
    }
}

// ---------- ChaCha20-Poly1305 negative tests ----------

BOOST_AUTO_TEST_CASE(chacha_decrypt_wrong_nonce_test)
{
    std::vector<uint8_t> plaintext{'p', 'a', 'y', 'l', 'o', 'a', 'd'};
    uint256 secret;
    GetStrongRandBytes(secret);
    std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce_a;
    GetStrongRandBytes(nonce_a);
    auto ct = EncryptChaCha20Poly1305(plaintext, secret, nonce_a);

    std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce_b;
    std::memset(nonce_b.data(), 0xF1, nonce_b.size());
    BOOST_CHECK(!DecryptChaCha20Poly1305(ct, secret, nonce_b).has_value());
}

BOOST_AUTO_TEST_CASE(chacha_decrypt_corrupted_test)
{
    std::vector<uint8_t> plaintext(32, 0x42);
    uint256 secret;
    GetStrongRandBytes(secret);
    std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce;
    GetStrongRandBytes(nonce);
    auto ct = EncryptChaCha20Poly1305(plaintext, secret, nonce);
    BOOST_REQUIRE(DecryptChaCha20Poly1305(ct, secret, nonce).has_value());
    ct.back() ^= 0x01;
    BOOST_CHECK(!DecryptChaCha20Poly1305(ct, secret, nonce).has_value());
}

BOOST_AUTO_TEST_CASE(full_backup_roundtrip_test)
{
    // Test full backup creation and decryption with a real descriptor
    // Use testnet tpub since we're running on RegTest
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";

    // Create backup
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);

    std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());

    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);

    auto backup_result = CreateEncryptedBackup(keys, plaintext, content, paths);
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    // Encode to binary
    auto encoded = EncodeEncryptedBackup(*backup_result);
    BOOST_REQUIRE_MESSAGE(encoded, util::ErrorString(encoded).original);
    BOOST_CHECK(!encoded->empty());

    // Check magic bytes
    BOOST_CHECK_EQUAL((*encoded)[0], 'B');
    BOOST_CHECK_EQUAL((*encoded)[1], 'I');
    BOOST_CHECK_EQUAL((*encoded)[2], 'P');

    // Decode back
    auto decoded_result = DecodeEncryptedBackup(*encoded);
    BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);

    // Decrypt using the same descriptor
    auto decrypted = DecryptBackupWithDescriptor(*decoded_result, descriptor);
    BOOST_REQUIRE_MESSAGE(decrypted, util::ErrorString(decrypted).original);

    // Verify plaintext matches
    std::string decrypted_str(decrypted->first.begin(), decrypted->first.end());
    BOOST_CHECK_EQUAL(decrypted_str, descriptor);
}

BOOST_AUTO_TEST_CASE(base64_encoding_test)
{
    // Test base64 encoding roundtrip
    // Use testnet tpub since we're running on RegTest
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";

    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);

    std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());

    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);

    auto backup_result = CreateEncryptedBackup(keys, plaintext, content, paths);
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    // Encode to base64
    auto base64_str = EncodeEncryptedBackupBase64(*backup_result);
    BOOST_REQUIRE_MESSAGE(base64_str, util::ErrorString(base64_str).original);
    BOOST_CHECK(!base64_str->empty());

    // Decode from base64
    auto decoded_result = DecodeEncryptedBackupBase64(*base64_str);
    BOOST_REQUIRE_MESSAGE(decoded_result, util::ErrorString(decoded_result).original);

    // Decrypt
    auto decrypted = DecryptBackupWithDescriptor(*decoded_result, descriptor);
    BOOST_REQUIRE_MESSAGE(decrypted, util::ErrorString(decrypted).original);

    std::string decrypted_str(decrypted->first.begin(), decrypted->first.end());
    BOOST_CHECK_EQUAL(decrypted_str, descriptor);
}

BOOST_AUTO_TEST_CASE(wrong_key_decryption_test)
{
    // Test that decryption fails with wrong key
    // Use testnet tpub keys since we're running on RegTest
    std::string descriptor1 = "wpkh([11111111/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    std::string descriptor2 = "wpkh([22222222/84h/1h/0h]tpubDCBEcmVKbfC9KfdydyLbJ2gfNL88grZu1XcWSW9ytTM6fitvaRmVyr8Ddf7SjZ2ZfMx9RicjYAXhuh3fmLiVLPodPEqnQQURUfrBKiiVZc8/0/*)";

    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);

    std::vector<uint8_t> plaintext(descriptor1.begin(), descriptor1.end());

    // Create backup with descriptor1
    auto [keys1, paths1] = *ExtractKeysFromDescriptor(descriptor1);
    auto backup_result = CreateEncryptedBackup(keys1, plaintext, content, paths1);
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    // Try to decrypt with descriptor2 - should fail
    auto decrypted = DecryptBackupWithDescriptor(*backup_result, descriptor2);
    BOOST_CHECK_MESSAGE(!decrypted, "Decryption should fail with wrong key");
}

BOOST_AUTO_TEST_CASE(encrypted_backup_vector_test)
{
    UniValue vectors = read_json(json_tests::bip_encrypted_backup_encrypted_backup);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& vec = vectors[i];
        std::string description = vec["description"].get_str();
        BOOST_TEST_MESSAGE("Testing: " << description);

        // Parse + normalize + sort keys.
        std::vector<uint256> keys;
        const UniValue& keys_arr = vec["keys"];
        for (size_t j = 0; j < keys_arr.size(); ++j) {
            auto bytes = ParseHex(keys_arr[j].get_str());
            BOOST_REQUIRE_EQUAL(bytes.size(), 33u);
            uint256 k;
            std::memcpy(k.data(), bytes.data() + 1, 32);
            keys.push_back(k);
        }
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());

        // Derivation paths: sort + dedupe to match the reference encoder.
        std::set<DerivationPath> path_set;
        const UniValue& paths_arr = vec["derivation_paths"];
        for (size_t j = 0; j < paths_arr.size(); ++j) {
            auto p = ParseDerivationPath(paths_arr[j].get_str());
            BOOST_REQUIRE(p);
            path_set.insert(*p);
        }
        std::vector<DerivationPath> paths(path_set.begin(), path_set.end());

        // Nonce.
        auto nonce_bytes = ParseHex(vec["nonce"].get_str());
        BOOST_REQUIRE_EQUAL(nonce_bytes.size(), AEADChaCha20Poly1305::NONCE_SIZE);
        std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce;
        std::memcpy(nonce.data(), nonce_bytes.data(), nonce.size());

        // Build payload: pre-encoded content || raw plaintext (UTF-8 bytes).
        auto content_bytes = ParseHex(vec["content"].get_str());
        std::string plaintext_str = vec["plaintext"].get_str();
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), content_bytes.begin(), content_bytes.end());
        payload.insert(payload.end(), plaintext_str.begin(), plaintext_str.end());

        // Compute secrets.
        uint256 s = ComputeDecryptionSecret(keys);
        auto individual_secrets = ComputeAllIndividualSecrets(s, keys);

        // Encrypt.
        auto ciphertext = EncryptChaCha20Poly1305(payload, s, nonce);

        // Assemble and encode.
        EncryptedBackup backup;
        backup.version = static_cast<uint8_t>(vec["version"].getInt<int>());
        backup.derivation_paths = paths;
        backup.individual_secrets = individual_secrets;
        backup.encryption = static_cast<EncryptionAlgorithm>(vec["encryption"].getInt<int>());
        backup.nonce = nonce;
        backup.ciphertext = std::move(ciphertext);

        auto encoded = EncodeEncryptedBackup(backup);
        BOOST_REQUIRE_MESSAGE(encoded, util::ErrorString(encoded).original);
        std::string expected_hex = vec["expected"].get_str();
        BOOST_CHECK_MESSAGE(HexStr(*encoded) == expected_hex,
            description << ": encoded mismatch\n  got:      " << HexStr(*encoded)
            << "\n  expected: " << expected_hex);

        // Round-trip decode.
        auto decoded = DecodeEncryptedBackup(*encoded);
        BOOST_REQUIRE_MESSAGE(decoded, util::ErrorString(decoded).original);

        // Trailing-byte tolerance.
        if (!vec["trailing"].isNull()) {
            auto trailing = ParseHex(vec["trailing"].get_str());
            std::vector<uint8_t> with_trailing = *encoded;
            with_trailing.insert(with_trailing.end(), trailing.begin(), trailing.end());
            auto decoded2 = DecodeEncryptedBackup(with_trailing);
            BOOST_CHECK_MESSAGE(static_cast<bool>(decoded2),
                description << ": decoder must tolerate trailing bytes");
        }

        // Decrypt using first key and check content + plaintext match.
        auto decrypted = DecryptBackupWithKey(*decoded, keys[0]);
        BOOST_REQUIRE_MESSAGE(decrypted.has_value(),
            description << ": DecryptBackupWithKey failed");
        std::string dec_str(decrypted->first.begin(), decrypted->first.end());
        BOOST_CHECK_EQUAL(dec_str, plaintext_str);
    }
}

// ---------- High-level wire parsing: magic/version/encryption byte ----------

BOOST_AUTO_TEST_CASE(decode_parse_magic_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt(descriptor.begin(), descriptor.end());
    auto backup = CreateEncryptedBackup(keys, pt, content, paths);
    BOOST_REQUIRE(backup);
    auto bytes = EncodeEncryptedBackup(*backup);
    BOOST_REQUIRE(bytes);
    auto bad = *bytes;
    bad[0] = 'B'; bad[1] = 'O'; bad[2] = 'B';
    BOOST_CHECK(!DecodeEncryptedBackup(bad));
}

BOOST_AUTO_TEST_CASE(decode_parse_version_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt(descriptor.begin(), descriptor.end());
    auto backup = CreateEncryptedBackup(keys, pt, content, paths);
    BOOST_REQUIRE(backup);
    auto bytes = EncodeEncryptedBackup(*backup);
    BOOST_REQUIRE(bytes);
    auto v0 = *bytes; v0[6] = 0x00;
    BOOST_CHECK(!DecodeEncryptedBackup(v0));
    auto v2 = *bytes; v2[6] = 0x02;
    BOOST_CHECK(!DecodeEncryptedBackup(v2));
}

BOOST_AUTO_TEST_CASE(decode_parse_encryption_reserved_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt(descriptor.begin(), descriptor.end());
    auto backup = CreateEncryptedBackup(keys, pt, content, paths);
    BOOST_REQUIRE(backup);
    auto bytes = EncodeEncryptedBackup(*backup);
    BOOST_REQUIRE(bytes);
    // Find encryption byte offset dynamically
    auto decoded = DecodeEncryptedBackup(*bytes);
    BOOST_REQUIRE(decoded);
    auto paths_enc = EncodeDerivationPaths(decoded->derivation_paths);
    BOOST_REQUIRE(paths_enc);
    auto secrets_enc = EncodeIndividualSecrets(decoded->individual_secrets);
    BOOST_REQUIRE(secrets_enc);
    size_t enc_off = 6 + 1 + paths_enc->size() + secrets_enc->size();
    BOOST_REQUIRE_EQUAL((*bytes)[enc_off], 0x01);
    auto reserved = *bytes; reserved[enc_off] = 0x00;
    BOOST_CHECK(!DecodeEncryptedBackup(reserved));
    auto unknown = *bytes; unknown[enc_off] = 0x02;
    BOOST_CHECK(!DecodeEncryptedBackup(unknown));
}

// ---------- High-level sanitizing ----------

BOOST_AUTO_TEST_CASE(encrypt_sanitizing_empty_keys_test)
{
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt{'x'};
    BOOST_CHECK(!CreateEncryptedBackup({}, pt, content, {}));
}

BOOST_AUTO_TEST_CASE(encrypt_sanitizing_zero_nonce_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt{'x'};
    std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce{};
    BOOST_CHECK(!CreateEncryptedBackupWithNonce(keys, pt, content, paths, nonce));
}

BOOST_AUTO_TEST_CASE(encrypt_sanitizing_empty_derivation_paths_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt{'x'};
    BOOST_CHECK(!CreateEncryptedBackup(keys, pt, content, {}));
}

BOOST_AUTO_TEST_CASE(encrypt_sanitizing_too_many_paths_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, _] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt{'x'};
    std::vector<DerivationPath> paths;
    for (size_t i = 0; i < 256; ++i) {
        paths.push_back(DerivationPath{static_cast<uint32_t>(i), 1u, 2u, 3u});
    }
    std::array<uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce{};
    nonce.fill(1);
    auto r = CreateEncryptedBackupWithNonce(keys, pt, content, paths, nonce);
    BOOST_REQUIRE(r);
    // Size is enforced at the wire-encoding layer.
    BOOST_CHECK(!EncodeEncryptedBackup(*r));
}

BOOST_AUTO_TEST_CASE(multi_recipient_decrypt_test)
{
    std::string descriptor = "wsh(multi(1,"
        "[d34db33f/48h/1h/0h/2h]tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/0/*,"
        "[11111111/48h/1h/0h/2h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*"
        "))";

    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> pt = {'h', 'e', 'l', 'l', 'o'};
    auto backup = CreateEncryptedBackup(keys, pt, content, paths);
    BOOST_REQUIRE_MESSAGE(backup, util::ErrorString(backup).original);
    BOOST_CHECK_EQUAL(backup->individual_secrets.size(), 2u);

    // Unrelated descriptor must fail to decrypt.
    std::string other = "wpkh([22222222/84h/1h/0h]tpubDCBEcmVKbfC9KfdydyLbJ2gfNL88grZu1XcWSW9ytTM6fitvaRmVyr8Ddf7SjZ2ZfMx9RicjYAXhuh3fmLiVLPodPEqnQQURUfrBKiiVZc8/0/*)";
    BOOST_CHECK(!DecryptBackupWithDescriptor(*backup, other));

    auto r = DecryptBackupWithDescriptor(*backup, descriptor);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(std::string(r->first.begin(), r->first.end()), "hello");
}

// ---------- ExtractKeysFromDescriptor / CreateEncryptedBackup error cases ----------

BOOST_AUTO_TEST_CASE(extract_keys_invalid_descriptor_test)
{
    BOOST_CHECK(!ExtractKeysFromDescriptor("not a descriptor"));
    BOOST_CHECK(!ExtractKeysFromDescriptor(""));
    BOOST_CHECK(!ExtractKeysFromDescriptor("wpkh()"));
}

BOOST_AUTO_TEST_CASE(extract_keys_nums_only_test)
{
    // tr(NUMS) is a valid descriptor whose sole key is the BIP341 NUMS point;
    // ExtractKeysFromDescriptor must filter it out and return an error since
    // no usable keys remain.
    std::string nums_only = "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)";
    BOOST_CHECK(!ExtractKeysFromDescriptor(nums_only));
}

BOOST_AUTO_TEST_CASE(create_backup_empty_plaintext_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    BOOST_CHECK(!CreateEncryptedBackup(keys, std::span<const uint8_t>{}, content, paths));
}

BOOST_AUTO_TEST_CASE(decode_base64_invalid_test)
{
    BOOST_CHECK(!DecodeEncryptedBackupBase64("!!!not-base64!!!"));
    BOOST_CHECK(!DecodeEncryptedBackupBase64(""));
}

BOOST_AUTO_TEST_CASE(decode_base64_valid_but_bad_payload_test)
{
    // Valid base64 of arbitrary bytes that don't match the backup format.
    BOOST_CHECK(!DecodeEncryptedBackupBase64("aGVsbG8gd29ybGQ=")); // "hello world"
}

BOOST_AUTO_TEST_CASE(decrypt_with_xpub_formats_test)
{
    // Test DecryptDescriptorWithXpub with various xpub input formats
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";

    // Create and encode backup
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    std::vector<uint8_t> plaintext(descriptor.begin(), descriptor.end());
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    auto backup_result = CreateEncryptedBackup(keys, plaintext, content, paths);
    BOOST_REQUIRE_MESSAGE(backup_result, util::ErrorString(backup_result).original);

    auto encoded = EncodeEncryptedBackup(*backup_result);
    BOOST_REQUIRE_MESSAGE(encoded, util::ErrorString(encoded).original);

    auto decoded = DecodeEncryptedBackup(*encoded);
    BOOST_REQUIRE_MESSAGE(decoded, util::ErrorString(decoded).original);

    // Bare tpub (no origin, no derivation path)
    {
        auto result = DecryptDescriptorWithXpub(*decoded,
            "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba");
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        BOOST_CHECK_EQUAL(*result, descriptor);
    }

    // With origin
    {
        auto result = DecryptDescriptorWithXpub(*decoded,
            "[d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba");
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        BOOST_CHECK_EQUAL(*result, descriptor);
    }

    // With origin and derivation path
    {
        auto result = DecryptDescriptorWithXpub(*decoded,
            "[d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*");
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        BOOST_CHECK_EQUAL(*result, descriptor);
    }

    // With derivation path only (no origin)
    {
        auto result = DecryptDescriptorWithXpub(*decoded,
            "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*");
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        BOOST_CHECK_EQUAL(*result, descriptor);
    }

    // Wrong xpub should fail
    {
        auto result = DecryptDescriptorWithXpub(*decoded,
            "tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x");
        BOOST_CHECK_MESSAGE(!result, "Decryption should fail with wrong xpub");
    }

    // Multipath derivation: encrypt a multipath descriptor and decrypt with the multipath xpub form
    {
        std::string multipath_descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/<0;1>/*)";
        auto [mp_keys, mp_paths] = *ExtractKeysFromDescriptor(multipath_descriptor);
        std::vector<uint8_t> mp_pt(multipath_descriptor.begin(), multipath_descriptor.end());
        auto mp_backup = CreateEncryptedBackup(mp_keys, mp_pt, content, mp_paths);
        BOOST_REQUIRE_MESSAGE(mp_backup, util::ErrorString(mp_backup).original);
        auto mp_encoded = EncodeEncryptedBackup(*mp_backup);
        BOOST_REQUIRE_MESSAGE(mp_encoded, util::ErrorString(mp_encoded).original);
        auto mp_decoded = DecodeEncryptedBackup(*mp_encoded);
        BOOST_REQUIRE_MESSAGE(mp_decoded, util::ErrorString(mp_decoded).original);

        auto result = DecryptDescriptorWithXpub(*mp_decoded,
            "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/<0;1>/*");
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        BOOST_CHECK_EQUAL(*result, multipath_descriptor);
    }
}

// ---------- DecryptDescriptorWithXpub error cases ----------

BOOST_AUTO_TEST_CASE(decrypt_xpub_invalid_string_test)
{
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    std::vector<uint8_t> pt(descriptor.begin(), descriptor.end());
    auto content = EncryptedBackupContent::Bip(BIP_DESCRIPTORS);
    auto backup = CreateEncryptedBackup(keys, pt, content, paths);
    BOOST_REQUIRE(backup);

    BOOST_CHECK(!DecryptDescriptorWithXpub(*backup, "not-an-xpub"));
    BOOST_CHECK(!DecryptDescriptorWithXpub(*backup, ""));
}

BOOST_AUTO_TEST_CASE(decrypt_xpub_content_mismatch_test)
{
    // Encrypt with a non-BIP_DESCRIPTORS content type (BIP_LABELS) and verify
    // DecryptDescriptorWithXpub rejects it because content type isn't descriptors.
    std::string descriptor = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    auto [keys, paths] = *ExtractKeysFromDescriptor(descriptor);
    std::vector<uint8_t> pt{'l', 'a', 'b', 'e', 'l', 's'};
    auto content = EncryptedBackupContent::Bip(BIP_LABELS);
    auto backup = CreateEncryptedBackup(keys, pt, content, paths);
    BOOST_REQUIRE(backup);

    auto result = DecryptDescriptorWithXpub(*backup,
        "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba");
    BOOST_CHECK_MESSAGE(!result, "Should fail with content type mismatch");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
