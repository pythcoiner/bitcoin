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

    def run_test(self):
        self.test_encryptdescriptor()
        self.test_encryptdescriptor_errors()


if __name__ == '__main__':
    WalletEncryptedBackupTest(__file__).main()
