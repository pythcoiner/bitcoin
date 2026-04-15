// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/encryptedbackup.h>

#include <cstring>
#include <set>

#include <crypto/chacha20poly1305.h>
#include <hash.h>
#include <key_io.h>
#include <random.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <streams.h>
#include <util/bip32.h>
#include <util/strencodings.h>

namespace wallet {

uint256 NormalizeToXOnly(const CPubKey& pubkey)
{
    // CPubKey is either compressed (33 bytes) or uncompressed (65 bytes)
    // In both cases, bytes 1-32 are the x-coordinate
    uint256 result;
    if (pubkey.size() >= 33) {
        std::memcpy(result.data(), pubkey.data() + 1, 32);
    }
    return result;
}

uint256 NormalizeToXOnly(const CExtPubKey& xpub)
{
    return NormalizeToXOnly(xpub.pubkey);
}

bool IsNUMSPoint(const uint256& key)
{
    // BIP341 NUMS point: 50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
    // Compare against XOnlyPubKey::NUMS_H
    XOnlyPubKey xonly{std::span<const unsigned char>{key.data(), 32}};
    return xonly == XOnlyPubKey::NUMS_H;
}

util::Result<std::pair<std::vector<uint256>, std::vector<DerivationPath>>> ExtractKeysFromDescriptor(const std::string& descriptor)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/false);
    if (parsed.empty()) {
        return util::Error{Untranslated(strprintf("Failed to parse descriptor: %s", error))};
    }

    std::set<CPubKey> pubkeys;
    std::set<CExtPubKey> xpubs;
    for (const auto& desc : parsed) {
        desc->GetPubKeys(pubkeys, xpubs);
    }

    // Normalize all keys to x-only format
    std::set<uint256> normalized_keys;
    for (const auto& pubkey : pubkeys) {
        uint256 xonly = NormalizeToXOnly(pubkey);
        // Skip NUMS point
        if (!IsNUMSPoint(xonly)) {
            normalized_keys.insert(xonly);
        }
    }
    for (const auto& xpub : xpubs) {
        uint256 xonly = NormalizeToXOnly(xpub);
        // Skip NUMS point
        if (!IsNUMSPoint(xonly)) {
            normalized_keys.insert(xonly);
        }
    }

    if (normalized_keys.empty()) {
        return util::Error{Untranslated("No valid public keys found in descriptor")};
    }

    // Expand the descriptor to populate key origins with derivation paths
    std::set<DerivationPath> unique_paths;
    for (const auto& desc : parsed) {
        FlatSigningProvider expanded;
        std::vector<CScript> scripts;
        desc->Expand(0, provider, scripts, expanded);
        for (const auto& [_, origin] : expanded.origins) {
            if (!origin.second.path.empty()) {
                unique_paths.insert(origin.second.path);
            }
        }
    }

    return std::make_pair(
        std::vector<uint256>(normalized_keys.begin(), normalized_keys.end()),
        std::vector<DerivationPath>(unique_paths.begin(), unique_paths.end()));
}

uint256 ComputeDecryptionSecret(const std::vector<uint256>& keys)
{
    // BIP340-style tagged hash: sha256(sha256(tag) || sha256(tag) || p1 || ... || pn)
    HashWriter hasher{TaggedHash(std::string{BIP_DECRYPTION_SECRET_TAG})};
    for (const auto& key : keys) {
        hasher << std::span{key.data(), 32};
    }
    return hasher.GetSHA256();
}

uint256 XorUint256(const uint256& a, const uint256& b)
{
    uint256 out;
    for (size_t i = 0; i < 32; ++i) {
        out.data()[i] = a.data()[i] ^ b.data()[i];
    }
    return out;
}

uint256 ComputeIndividualSecret(const uint256& key)
{
    // BIP340-style tagged hash: sha256(sha256(tag) || sha256(tag) || pi)
    HashWriter hasher{TaggedHash(std::string{BIP_INDIVIDUAL_SECRET_TAG})};
    hasher << std::span{key.data(), 32};
    return hasher.GetSHA256();
}

std::vector<uint256> ComputeAllIndividualSecrets(const uint256& decryption_secret,
                                                  const std::vector<uint256>& keys)
{
    std::vector<uint256> result;
    result.reserve(keys.size());

    for (const auto& key : keys) {
        uint256 si = ComputeIndividualSecret(key);
        // ci = s XOR si
        result.push_back(XorUint256(decryption_secret, si));
    }
    return result;
}

util::Result<DerivationPath> ParseDerivationPath(const std::string& path_str)
{
    DerivationPath result;
    if (path_str.empty() || !ParseHDKeypath(path_str, result)) {
        return util::Error{Untranslated(strprintf("Invalid derivation path: %s", path_str))};
    }
    return result;
}

// <COUNT><CHILD_COUNT><CHILD>...<CHILD><CHILD_COUNT><CHILD>...<CHILD>
util::Result<std::vector<uint8_t>> EncodeDerivationPaths(const std::vector<DerivationPath>& paths)
{
    if (paths.size() > 255) {
        return util::Error{Untranslated("Too many derivation paths (max 255)")};
    }

    std::vector<uint8_t> result;
    // <COUNT>
    result.push_back(static_cast<uint8_t>(paths.size()));

    for (const auto& path : paths) {
        if (path.size() > 255) {
            return util::Error{Untranslated("Derivation path too long (max 255 child)")};
        }
        // <CHILD_COUNT>
        result.push_back(static_cast<uint8_t>(path.size()));
        for (uint32_t child : path) {
            // <CHILD> (Big Endian)
            result.push_back((child >> 24) & 0xFF);
            result.push_back((child >> 16) & 0xFF);
            result.push_back((child >> 8) & 0xFF);
            result.push_back(child & 0xFF);
        }
    }

    return result;
}

util::Result<std::pair<std::vector<DerivationPath>, size_t>> DecodeDerivationPaths(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return util::Error{Untranslated("Empty derivation paths data")};
    }

    // Parsed paths are deduplicated and sorted on decode, matching the
    // reference implementation's BTreeSet behavior.
    std::set<DerivationPath> unique_paths;
    size_t pos = 0;

    uint8_t count = data[pos++];

    for (uint8_t i = 0; i < count; ++i) {
        if (pos >= data.size()) {
            return util::Error{Untranslated("Truncated derivation path data")};
        }

        uint8_t child_count = data[pos++];
        if (child_count == 0) {
            return util::Error{Untranslated("Child count must be > 0")};
        }

        DerivationPath path;
        path.reserve(child_count);

        for (uint8_t j = 0; j < child_count; ++j) {
            if (pos + 4 > data.size()) {
                return util::Error{Untranslated("Truncated child index")};
            }
            uint32_t child = (static_cast<uint32_t>(data[pos]) << 24) |
                            (static_cast<uint32_t>(data[pos + 1]) << 16) |
                            (static_cast<uint32_t>(data[pos + 2]) << 8) |
                            static_cast<uint32_t>(data[pos + 3]);
            pos += 4;
            path.push_back(child);
        }
        unique_paths.insert(std::move(path));
    }

    return std::make_pair(std::vector<DerivationPath>(unique_paths.begin(), unique_paths.end()), pos);
}

util::Result<std::vector<uint8_t>> EncodeIndividualSecrets(const std::vector<uint256>& secrets)
{
    // Deduplicate and sort lexicographically.
    std::set<uint256> unique_secrets(secrets.begin(), secrets.end());
    if (unique_secrets.empty()) {
        return util::Error{Untranslated("At least one individual secret is required")};
    }
    if (unique_secrets.size() > 255) {
        return util::Error{Untranslated("Too many individual secrets (max 255)")};
    }

    std::vector<uint8_t> result;
    result.reserve(1 + unique_secrets.size() * SECRET_SIZE);
    result.push_back(static_cast<uint8_t>(unique_secrets.size()));

    for (const auto& secret : unique_secrets) {
        result.insert(result.end(), secret.begin(), secret.end());
    }

    return result;
}

util::Result<std::pair<std::vector<uint256>, size_t>> DecodeIndividualSecrets(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return util::Error{Untranslated("Empty individual secrets data")};
    }

    uint8_t count = data[0];
    if (count == 0) {
        return util::Error{Untranslated("At least one individual secret is required")};
    }

    size_t expected_size = 1 + count * SECRET_SIZE;
    if (data.size() < expected_size) {
        return util::Error{Untranslated("Truncated individual secrets data")};
    }

    // Parsed secrets are deduplicated and sorted on decode, matching the
    // reference implementation's BTreeSet behavior.
    std::set<uint256> unique_secrets;
    for (size_t i = 0; i < count; ++i) {
        uint256 secret;
        std::memcpy(secret.data(), data.data() + 1 + i * SECRET_SIZE, SECRET_SIZE);
        unique_secrets.insert(secret);
    }

    return std::make_pair(std::vector<uint256>(unique_secrets.begin(), unique_secrets.end()), expected_size);
}

util::Result<std::vector<uint8_t>> EncodeContent(const EncryptedBackupContent& content)
{
    std::vector<uint8_t> result;

    switch (content.type) {
    case ContentType::RESERVED:
        return util::Error{Untranslated("Reserved content type cannot be encoded")};

    case ContentType::BIP_NUMBER:
        result.push_back(static_cast<uint8_t>(ContentType::BIP_NUMBER));
        // BIP number is big-endian uint16, no LENGTH field
        result.push_back((content.bip_number >> 8) & 0xFF);
        result.push_back(content.bip_number & 0xFF);
        break;

    case ContentType::VENDOR_SPECIFIC: {
        result.push_back(static_cast<uint8_t>(ContentType::VENDOR_SPECIFIC));
        // CompactSize encoding for length
        DataStream ss;
        WriteCompactSize(ss, content.vendor_data.size());
        result.insert(result.end(), UCharCast(ss.data()), UCharCast(ss.data()) + ss.size());
        result.insert(result.end(), content.vendor_data.begin(), content.vendor_data.end());
        break;
    }

    default:
        return util::Error{Untranslated("Unknown content type")};
    }

    return result;
}

util::Result<std::pair<EncryptedBackupContent, size_t>> DecodeContent(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return util::Error{Untranslated("Empty content data")};
    }

    const uint8_t type_byte = data[0];
    if (type_byte == 0x00) {
        return util::Error{Untranslated("Reserved content type 0x00")};
    }
    if (type_byte >= 0x80) {
        return util::Error{Untranslated("Content type >= 0x80 stops parsing")};
    }

    EncryptedBackupContent content;
    content.type = static_cast<ContentType>(type_byte);
    SpanReader reader{data.subspan(1)};

    if (content.type == ContentType::BIP_NUMBER) {
        if (reader.size() < 2) {
            return util::Error{Untranslated("Truncated BIP_NUMBER content")};
        }
        // BIP number is big-endian uint16, read manually
        uint8_t hi, lo;
        reader >> hi >> lo;
        content.bip_number = (static_cast<uint16_t>(hi) << 8) | lo;
    } else {
        uint64_t length;
        try {
            length = ReadCompactSize(reader);
        } catch (const std::ios_base::failure& e) {
            return util::Error{Untranslated(strprintf("Failed to decode content length: %s", e.what()))};
        }
        if (length > reader.size()) {
            return util::Error{Untranslated("Content data exceeds remaining bytes")};
        }
        if (content.type == ContentType::VENDOR_SPECIFIC) {
            content.vendor_data.resize(length);
            reader.read(MakeWritableByteSpan(content.vendor_data));
        } else {
            // Unknown type < 0x80: skip the payload
            reader.ignore(length);
        }
    }

    return std::make_pair(content, data.size() - reader.size());
}

namespace {
// Build a ChaCha20 Nonce96 from a 12-byte nonce using the RFC 8439 convention
// (state[13..16] = LE32(nonce[0..4]), LE32(nonce[4..8]), LE32(nonce[8..12])).
// Bitcoin Core's AEADChaCha20Poly1305::NonceFromBytes uses a big-endian +
// swapped-word layout suited to BIP324; it is not interoperable with RFC 8439,
// which is the construction BIP encrypted backup relies on.
AEADChaCha20Poly1305::Nonce96 Rfc8439Nonce(std::span<const uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> n)
{
    auto le32 = [&](size_t off) -> uint32_t {
        return uint32_t(n[off])
            | (uint32_t(n[off + 1]) << 8)
            | (uint32_t(n[off + 2]) << 16)
            | (uint32_t(n[off + 3]) << 24);
    };
    uint32_t w0 = le32(0);
    uint32_t w1 = le32(4);
    uint32_t w2 = le32(8);
    return {w0, uint64_t(w1) | (uint64_t(w2) << 32)};
}
} // namespace

std::vector<uint8_t> EncryptChaCha20Poly1305(std::span<const uint8_t> plaintext,
                                              const uint256& secret,
                                              std::span<const uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce)
{
    // Convert secret to byte span
    std::array<std::byte, SECRET_SIZE> key_bytes;
    std::memcpy(key_bytes.data(), secret.data(), SECRET_SIZE);

    // Initialize AEAD
    AEADChaCha20Poly1305 aead{key_bytes};

    auto nonce96 = Rfc8439Nonce(nonce);

    // Convert plaintext to byte span
    std::vector<std::byte> plain_bytes(plaintext.size());
    std::memcpy(plain_bytes.data(), plaintext.data(), plaintext.size());

    // Allocate output (plaintext + 16-byte tag)
    std::vector<std::byte> cipher_bytes(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);

    // Encrypt with empty AAD
    aead.Encrypt(plain_bytes, {}, nonce96, cipher_bytes);

    // Convert back to uint8_t
    std::vector<uint8_t> result(cipher_bytes.size());
    std::memcpy(result.data(), cipher_bytes.data(), cipher_bytes.size());

    return result;
}

std::optional<std::vector<uint8_t>> DecryptChaCha20Poly1305(std::span<const uint8_t> ciphertext,
                                                             const uint256& secret,
                                                             std::span<const uint8_t, AEADChaCha20Poly1305::NONCE_SIZE> nonce)
{
    if (ciphertext.size() < AEADChaCha20Poly1305::EXPANSION) {
        return std::nullopt;
    }

    // Convert secret to byte span
    std::array<std::byte, SECRET_SIZE> key_bytes;
    std::memcpy(key_bytes.data(), secret.data(), SECRET_SIZE);

    // Initialize AEAD
    AEADChaCha20Poly1305 aead{key_bytes};

    auto nonce96 = Rfc8439Nonce(nonce);

    // Convert ciphertext to byte span
    std::vector<std::byte> cipher_bytes(ciphertext.size());
    std::memcpy(cipher_bytes.data(), ciphertext.data(), ciphertext.size());

    // Allocate output
    std::vector<std::byte> plain_bytes(ciphertext.size() - AEADChaCha20Poly1305::EXPANSION);

    // Decrypt with empty AAD
    if (!aead.Decrypt(cipher_bytes, {}, nonce96, plain_bytes)) {
        return std::nullopt;
    }

    // Convert back to uint8_t
    std::vector<uint8_t> result(plain_bytes.size());
    std::memcpy(result.data(), plain_bytes.data(), plain_bytes.size());

    return result;
}

} // namespace wallet
