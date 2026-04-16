#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the encryptdescriptor, decryptdescriptor, importencrypteddescriptor, and inspectencrypteddescriptor RPCs."""

import base64
import os
import re

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletEncryptedBackupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_encryptdescriptor(self):
        self.log.info("Test encryptdescriptor RPC")

        wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        descriptors = wallet.listdescriptors()["descriptors"]

        # Pick a descriptor that contains a tpub/xpub (has derivation paths)
        chosen_desc = None
        xpub_match = None
        for desc_obj in descriptors:
            m = re.search(r'[tx]pub[A-Za-z0-9]+', desc_obj["desc"])
            if m:
                chosen_desc = desc_obj["desc"]
                xpub_match = m
                break
        assert chosen_desc is not None, "Could not find a descriptor with tpub/xpub"
        self.xpub = xpub_match.group(0)

        # Encrypt via RPC
        backup_base64 = self.nodes[0].encryptdescriptor(chosen_desc)

        # Verify it's valid base64 with BIP magic
        backup_bytes = base64.b64decode(backup_base64)
        assert backup_bytes[:6] == b"BIPXXX", f"Expected magic 'BIPXXX', got: {backup_bytes[:6]}"

        # Store for use by later tests
        self.chosen_desc = chosen_desc
        self.backup_base64 = backup_base64

        # Test encrypt to file via backupfile
        self.log.info("Testing encryptdescriptor with backupfile...")
        backup_file = str(self.nodes[0].datadir_path / "rpc_backup.bin")
        result = self.nodes[0].encryptdescriptor(chosen_desc, backup_file)
        assert_equal(result["filename"], backup_file)

        import os
        raw_bytes = open(backup_file, "rb").read()
        assert len(raw_bytes) > 0
        assert_equal(raw_bytes[:6], b"BIPXXX")
        self.backup_file = backup_file

        self.log.info("encryptdescriptor RPC test passed!")

    def test_encryptdescriptor_errors(self):
        self.log.info("Test encryptdescriptor RPC error cases")
        node = self.nodes[0]

        # Invalid descriptor (unparseable string)
        assert_raises_rpc_error(-5, "Invalid descriptor",
                                node.encryptdescriptor, "this is not a descriptor")
        # Descriptor with no extractable key
        assert_raises_rpc_error(-5, "Invalid descriptor",
                                node.encryptdescriptor, "wpkh()")
        # Backup file already exists
        existing_file = str(node.datadir_path / "rpc_existing.bin")
        with open(existing_file, "wb") as f:
            f.write(b"placeholder")
        assert_raises_rpc_error(-8, "already exists",
                                node.encryptdescriptor, self.chosen_desc, existing_file)
        os.remove(existing_file)

        self.log.info("encryptdescriptor RPC error cases passed!")

    def _xpub_format_variants(self):
        """Return a list of (label, xpub_form) pairs derived from self.chosen_desc."""
        m = re.match(r'^[a-z]+\(\[(?P<origin>[^\]]+)\](?P<xpub>[tx]pub[A-Za-z0-9]+)(?P<deriv>/[^)]*)?\)', self.chosen_desc)
        assert m is not None, f"Failed to parse chosen_desc: {self.chosen_desc}"
        origin = m.group("origin")
        xpub = m.group("xpub")
        deriv = m.group("deriv") or "/0/*"
        return [
            ("bare", xpub),
            ("with_origin", f"[{origin}]{xpub}"),
            ("with_deriv", f"{xpub}{deriv}"),
            ("with_origin_and_deriv", f"[{origin}]{xpub}{deriv}"),
            ("multipath", f"{xpub}/<0;1>/*"),
        ]

    def test_decryptdescriptor(self):
        self.log.info("Test decryptdescriptor RPC")

        # Decrypt from base64
        decrypted = self.nodes[0].decryptdescriptor(self.backup_base64, self.xpub)
        assert_equal(decrypted, self.chosen_desc)

        # Decrypt from file
        decrypted_from_file = self.nodes[0].decryptdescriptor("", self.xpub, self.backup_file)
        assert_equal(decrypted_from_file, self.chosen_desc)

        self.log.info("decryptdescriptor RPC test passed!")

    def test_decryptdescriptor_xpub_formats(self):
        self.log.info("Test decryptdescriptor xpub format coverage")
        node = self.nodes[0]
        for label, x in self._xpub_format_variants():
            result = node.decryptdescriptor(self.backup_base64, x)
            assert_equal(result, self.chosen_desc)
            self.log.info(f"  decryptdescriptor with {label} xpub: OK")

    def test_decryptdescriptor_errors(self):
        self.log.info("Test decryptdescriptor RPC error cases")
        node = self.nodes[0]
        bad_b64 = "not!valid!base64!"
        valid_b64_bad_payload = base64.b64encode(b"hello world").decode()
        nonexistent_file = str(node.datadir_path / "does_not_exist.bin")
        wrong_xpub = "tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x"

        assert_raises_rpc_error(-22, "Failed to decode backup",
                                node.decryptdescriptor, bad_b64, self.xpub)
        assert_raises_rpc_error(-22, "Failed to decode backup",
                                node.decryptdescriptor, valid_b64_bad_payload, self.xpub)
        assert_raises_rpc_error(-4, "Failed to decrypt",
                                node.decryptdescriptor, self.backup_base64, wrong_xpub)
        assert_raises_rpc_error(-4, "Invalid extended public key",
                                node.decryptdescriptor, self.backup_base64, "garbage-xpub")
        assert_raises_rpc_error(-8, "Pass either backup or backupfile, but not both",
                                node.decryptdescriptor, self.backup_base64, self.xpub, self.backup_file)
        assert_raises_rpc_error(-8, "Pass either backup or backupfile, but not both",
                                node.decryptdescriptor, "", self.xpub)
        assert_raises_rpc_error(-22, "Unable to open",
                                node.decryptdescriptor, "", self.xpub, nonexistent_file)

        self.log.info("decryptdescriptor RPC error cases passed!")

    def run_test(self):
        self.test_encryptdescriptor()
        self.test_encryptdescriptor_errors()
        self.test_decryptdescriptor()
        self.test_decryptdescriptor_xpub_formats()
        self.test_decryptdescriptor_errors()


if __name__ == '__main__':
    WalletEncryptedBackupTest(__file__).main()
