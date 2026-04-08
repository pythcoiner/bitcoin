#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the importwalletbackup RPC."""

import json
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletImportBackupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        return

    def run_test(self):
        node = self.nodes[0]

        # Source wallet: generate activity across output types, with a label
        # and a spend.
        node.createwallet(wallet_name='src')
        src = node.get_wallet_rpc('src')
        addr_main = src.getnewaddress(label='savings', address_type='bech32m')
        self.generatetoaddress(node, 101, addr_main)
        addr_other = src.getnewaddress(address_type='bech32')
        txid_spend = src.sendtoaddress(address=addr_other, amount=1)
        self.generate(node, 1)

        backup_path = os.path.join(self.options.tmpdir, 'src-backup.json')
        src.exportwalletbackup(backup_path)

        with open(backup_path, 'r', encoding='utf-8') as f:
            backup_json = json.load(f)
        assert_equal(backup_json['version'], 1)
        src_balance = src.getbalance()

        self.log.info("Fast-path round trip with rescan=auto (file source).")
        result = node.importwalletbackup(backup_path, "restored_auto")
        assert_equal(result['name'], 'restored_auto')
        restored = node.get_wallet_rpc('restored_auto')
        restored_descs = [d['desc'] for d in restored.listdescriptors()['descriptors']]
        src_descs = [d['desc'] for d in src.listdescriptors()['descriptors']]
        assert_equal(sorted(restored_descs), sorted(src_descs))
        assert_equal(restored.getbalance(), src_balance)
        assert_equal(restored.getaddressesbylabel('savings'), src.getaddressesbylabel('savings'))
        # The spend tx must be known to the restored wallet.
        assert restored.gettransaction(txid_spend)['txid'] == txid_spend

        self.log.info("Forced full rescan with rescan=force.")
        result = node.importwalletbackup(backup_path, "restored_force", "force")
        forced = node.get_wallet_rpc('restored_force')
        assert_equal(forced.getbalance(), src_balance)

        self.log.info("rescan=none imports descriptors+txs without scanning.")
        result = node.importwalletbackup(backup_path, "restored_none", "none")
        none_w = node.get_wallet_rpc('restored_none')
        # transactions[] is complete in the backup, so balance must still match.
        assert_equal(none_w.getbalance(), src_balance)

        self.log.info("Inline JSON source works.")
        inline = json.dumps(backup_json)
        node.importwalletbackup(inline, "restored_inline")
        assert_equal(node.get_wallet_rpc('restored_inline').getbalance(), src_balance)

        self.log.info("Existing wallet name is rejected.")
        assert_raises_rpc_error(-4, "already exists", node.importwalletbackup, backup_path, "restored_auto")

        self.log.info("Invalid rescan mode is rejected.")
        assert_raises_rpc_error(-8, "rescan must be one of", node.importwalletbackup, backup_path, "restored_bogus", "maybe")

        self.log.info("Network mismatch is rejected.")
        mutated = dict(backup_json)
        mutated['network'] = 'bitcoin'
        assert_raises_rpc_error(-8, "does not match current network",
                                node.importwalletbackup, json.dumps(mutated), "restored_netfail")


if __name__ == '__main__':
    WalletImportBackupTest(__file__).main()
