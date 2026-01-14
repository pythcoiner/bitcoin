// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ENCRYPTEDBACKUP_H
#define BITCOIN_WALLET_ENCRYPTEDBACKUP_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <pubkey.h>
#include <uint256.h>
#include <util/result.h>

namespace wallet {

const size_t SECRET_SIZE = 32;

/**
 * Implements the encrypted backup scheme from BIP-XXXX (draft).
 *
 * This provides encryption for wallet descriptors, labels, and other metadata
 * that can be safely stored in untrusted locations. The encryption key is derived
 * from the public keys in the descriptor, allowing any keyholder to decrypt
 * without additional secrets.
 *
 * IMPORTANT: This format intentionally does NOT backup private key material.
 * Restoring from an encrypted backup creates a watch-only wallet.
 */

/** Prefix for deriving the decryption secret */
static constexpr std::string_view BIP_DECRYPTION_SECRET_TAG = "BIPXXX_DECRYPTION_SECRET";

/** Prefix for deriving individual secrets */
static constexpr std::string_view BIP_INDIVIDUAL_SECRET_TAG = "BIPXXX_INDIVIDUAL_SECRET";

/**
 * Represents a parsed derivation path (e.g., m/44'/0'/0').
 * Each element is a 32-bit child index where hardened indices have the high bit set.
 */
using DerivationPath = std::vector<uint32_t>;

/**
 * Normalize a public key to 32-byte x-only format.
 *
 * Handles:
 * - Extended public keys (xpubs): extracts the pubkey and returns x-coordinate
 * - Compressed public keys (33 bytes): strips the prefix byte
 * - X-only public keys (32 bytes): returns as-is
 * - Uncompressed public keys (65 bytes): extracts the x-coordinate
 *
 * @param[in] pubkey The public key to normalize
 * @return The 32-byte x-only representation
 */
uint256 NormalizeToXOnly(const CPubKey& pubkey);

/**
 * Normalize an extended public key to 32-byte x-only format.
 *
 * @param[in] xpub The extended public key to normalize
 * @return The 32-byte x-only representation of the root pubkey
 */
uint256 NormalizeToXOnly(const CExtPubKey& xpub);

/**
 * Check if an x-only key is the BIP341 NUMS point (unspendable).
 *
 * @param[in] key The x-only key to check
 * @return true if this is the NUMS point
 */
bool IsNUMSPoint(const uint256& key);

/**
 * Extract and normalize all public keys and derivation paths from a descriptor string.
 *
 * Keys are sorted lexicographically and deduplicated. The NUMS point is excluded.
 * Derivation paths are extracted from key origins, deduplicated and sorted.
 *
 * @param[in] descriptor The descriptor string
 * @return Pair of (normalized x-only public keys, derivation paths), or error message
 */
util::Result<std::pair<std::vector<uint256>, std::vector<DerivationPath>>> ExtractKeysFromDescriptor(const std::string& descriptor);

/**
 * Compute the decryption secret from a set of public keys.
 *
 * s = tagged_hash("BIPXXX_DECRYPTION_SECRET", p1 || p2 || ... || pn)
 * where tagged_hash is BIP340-style (sha256(sha256(tag) || sha256(tag) || data))
 * and p1...pn are sorted lexicographically.
 *
 * @param[in] keys The normalized x-only public keys (must be sorted)
 * @return The 32-byte decryption secret
 */
uint256 ComputeDecryptionSecret(const std::vector<uint256>& keys);

/**
 * Compute an individual secret for a specific public key.
 *
 * si = tagged_hash("BIPXXX_INDIVIDUAL_SECRET", pi) (BIP340-style)
 *
 * @param[in] key The normalized x-only public key
 * @return The 32-byte individual secret
 */
uint256 ComputeIndividualSecret(const uint256& key);

/**
 * Compute all individual secrets from the decryption secret and keys.
 *
 * ci = s XOR si
 *
 * @param[in] decryption_secret The decryption secret
 * @param[in] keys The normalized x-only public keys
 * @return Vector of individual secrets (ci values)
 */
std::vector<uint256> ComputeAllIndividualSecrets(const uint256& decryption_secret,
                                                  const std::vector<uint256>& keys);

/**
 * Parse a derivation path string (e.g., "m/44'/0'/0'") into a DerivationPath.
 *
 * @param[in] path_str The path string to parse
 * @return The parsed path, or error message
 */
util::Result<DerivationPath> ParseDerivationPath(const std::string& path_str);

/**
 * Encode derivation paths according to the backup format.
 *
 * @param[in] paths Vector of derivation paths
 * @return Encoded bytes, or error if too many paths
 */
util::Result<std::vector<uint8_t>> EncodeDerivationPaths(const std::vector<DerivationPath>& paths);

/**
 * Decode derivation paths from backup format.
 *
 * @param[in] data The encoded data
 * @return Pair of (derivation paths, bytes consumed), or error message
 */
util::Result<std::pair<std::vector<DerivationPath>, size_t>> DecodeDerivationPaths(std::span<const uint8_t> data);

/**
 * Encode individual secrets according to the backup format.
 *
 * @param[in] secrets Vector of individual secrets
 * @return Encoded bytes, or error if empty or too many secrets
 */
util::Result<std::vector<uint8_t>> EncodeIndividualSecrets(const std::vector<uint256>& secrets);

/**
 * Decode individual secrets from backup format.
 *
 * @param[in] data The encoded data
 * @return Pair of (individual secrets, bytes consumed), or error message
 */
util::Result<std::pair<std::vector<uint256>, size_t>> DecodeIndividualSecrets(std::span<const uint8_t> data);

} // namespace wallet

#endif // BITCOIN_WALLET_ENCRYPTEDBACKUP_H
