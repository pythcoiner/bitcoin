#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the exportwalletbackup RPC."""

import json
import os

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletExportBackupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        return

    def run_test(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-18, 'No wallet is loaded.', node.exportwalletbackup)

        self.log.info("Create a fresh descriptor wallet with all default account types.")
        node.createwallet(wallet_name='w')
        w = node.get_wallet_rpc('w')

        # Drive each receive chain a different number of times so the resulting
        # `receive_index` values differ across accounts.
        addr_legacy = w.getnewaddress(label='legacy-label', address_type='legacy')
        for _ in range(2):
            w.getnewaddress(address_type='p2sh-segwit')
        for _ in range(3):
            w.getnewaddress(address_type='bech32')
        for _ in range(4):
            addr_taproot = w.getnewaddress(label='taproot-label', address_type='bech32m')

        # Fund the wallet and create a spend so transactions[] is non-empty and
        # exercises the change keypool.
        self.generatetoaddress(node, 101, addr_taproot)
        txid = w.sendtoaddress(address=addr_legacy, amount=1, comment="lunch", comment_to="alice")
        self.generate(node, 1)

        # Add an extra imported descriptor with an explicit, different timestamp
        # and a non-zero range_start, so the export covers heterogeneous accounts.
        xprv = "tprv8ZgxMBicQKsPeuVhWwi6wuMQGfPKi9Li5GtX35jVNknACgqe3CY4g5xgkfDDJcmtF7o1QnxWDRYw4H5P26PXq7sbcUkEqeR4fg3Kxp2tigg"
        imported_desc = descsum_create(f"wpkh({xprv}/0/*)")
        custom_timestamp = 1700000000
        result = w.importdescriptors([{
            "desc": imported_desc,
            "active": False,
            "timestamp": custom_timestamp,
            "range": [5, 20],
        }])
        assert result[0]['success'], result

        self.log.info("Call exportwalletbackup with no path -> JSON returned inline.")
        backup = w.exportwalletbackup()

        assert_equal(backup['version'], 1)
        assert_equal(backup['network'], 'regtest')
        assert_equal(backup['name'], 'w')

        accounts = backup['accounts']
        active = [a for a in accounts if a['active']]
        inactive = [a for a in accounts if not a['active']]

        # Every default output type must show up as an active paired account.
        active_output_types = {a['output_type'] for a in active}
        assert_equal(active_output_types, {'legacy', 'p2sh-segwit', 'bech32', 'bech32m'})

        for a in active:
            assert_equal(a['type'], 'bip_380')
            assert 'descriptor' in a and 'change_descriptor' in a
            assert 'descriptor_id' in a and 'change_descriptor_id' in a
            assert a['descriptor_id'] != a['change_descriptor_id']
            assert 'timestamp' in a and 'iso_8601_datetime' in a
            assert a['receive_index'] >= 0 and a['change_index'] >= 0

        # The receive_index values must differ since we drove each chain a
        # different number of times.
        by_type = {a['output_type']: a for a in active}
        receive_indices = {ot: by_type[ot]['receive_index'] for ot in active_output_types}
        assert len(set(receive_indices.values())) >= 3, receive_indices

        # The spend's change must have advanced at least one change chain.
        change_indices = {ot: by_type[ot]['change_index'] for ot in active_output_types}
        assert any(v > 0 for v in change_indices.values()), change_indices

        # The imported, inactive descriptor must appear with its custom timestamp
        # and non-zero range_start.
        imported_accounts = [a for a in inactive if a.get('timestamp') == custom_timestamp]
        assert_equal(len(imported_accounts), 1)
        imp = imported_accounts[0]
        assert_equal(imp['receive_range_start'], 5)
        assert imp['receive_range_end'] >= 20
        assert imp['iso_8601_datetime'].startswith('2023-')

        # Both labels must round-trip into bip329_labels.
        labels = backup['bip329_labels']
        label_pairs = {(e['ref'], e['label']) for e in labels if e['type'] == 'addr'}
        assert (addr_legacy, 'legacy-label') in label_pairs, labels
        assert (addr_taproot, 'taproot-label') in label_pairs, labels

        # transactions: our send must appear, with hex and confirmation info.
        txs = backup['transactions']
        sent = [t for t in txs if t['txid'] == txid]
        assert_equal(len(sent), 1)
        assert 'hex' in sent[0]
        assert 'blockhash' in sent[0]
        assert 'blockheight' in sent[0]
        # Tx comment is exported as a BIP-329 type:"tx" label.
        assert any(
            e['type'] == 'tx' and e['ref'] == txid and e['label'] == 'lunch'
            for e in labels
        ), labels

        # wallet_flags must include the descriptor flag.
        assert 'descriptor_wallet' in backup['wallet_flags']

        # bitcoin_conf must be present and must NOT contain credential-bearing
        # settings (the regtest config sets rpcuser/rpcpassword via the test
        # framework, so we explicitly assert they are stripped).
        assert 'bitcoin_conf' in backup
        for sensitive in ('rpcpassword', 'rpcauth', 'rpcuser'):
            assert sensitive not in backup['bitcoin_conf'], backup['bitcoin_conf']

        # last_height must reflect the current chain tip.
        assert_equal(backup['last_height'], node.getblockcount())

        self.log.info("Call exportwalletbackup with a file path -> file is written and matches inline JSON.")
        out_path = os.path.join(self.options.tmpdir, 'wallet_backup.json')
        result = w.exportwalletbackup(out_path)
        assert_equal(result, None)
        with open(out_path, 'r', encoding='utf-8') as f:
            file_backup = json.load(f)
        # Wallet state did not change between the two calls.
        assert_equal(file_backup, backup)

        self.log.info("Refuses to overwrite an existing file.")
        assert_raises_rpc_error(-8, "already exists", w.exportwalletbackup, out_path)


if __name__ == '__main__':
    WalletExportBackupTest(__file__).main()
