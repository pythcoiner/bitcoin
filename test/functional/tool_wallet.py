#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bitcoin-wallet."""

import os
import stat
import subprocess
import textwrap

from collections import OrderedDict

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    sha256sum_file,
)


class ToolWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_wallet_tool()

    def bitcoin_wallet_process(self, *args):
        default_args = ['-datadir={}'.format(self.nodes[0].datadir_path), '-chain=%s' % self.chain]

        return subprocess.Popen(self.get_binaries().wallet_argv() + default_args + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def assert_raises_tool_error(self, error, *args):
        p = self.bitcoin_wallet_process(*args)
        stdout, stderr = p.communicate()
        assert_equal(stdout, '')
        if isinstance(error, tuple):
            assert_equal(p.poll(), error[0])
            assert error[1] in stderr.strip()
        else:
            assert_equal(p.poll(), 1)
            assert error in stderr.strip()

    def assert_tool_output(self, output, *args):
        p = self.bitcoin_wallet_process(*args)
        stdout, stderr = p.communicate()
        assert_equal(stderr, '')
        assert_equal(stdout, output)
        assert_equal(p.poll(), 0)

    def wallet_shasum(self):
        return sha256sum_file(self.wallet_path).hex()

    def wallet_timestamp(self):
        return os.path.getmtime(self.wallet_path)

    def wallet_permissions(self):
        return oct(os.lstat(self.wallet_path).st_mode)[-3:]

    def log_wallet_timestamp_comparison(self, old, new):
        result = 'unchanged' if new == old else 'increased!'
        self.log.debug('Wallet file timestamp {}'.format(result))

    def get_expected_info_output(self, name="", transactions=0, keypool=2, address=0, imported_privs=0):
        wallet_name = self.default_wallet_name if name == "" else name
        output_types = 4  # p2pkh, p2sh, segwit, bech32m
        return textwrap.dedent('''\
            Wallet info
            ===========
            Name: %s
            Format: sqlite
            Descriptors: yes
            Encrypted: no
            HD (hd seed available): yes
            Keypool Size: %d
            Transactions: %d
            Address Book: %d
        ''' % (wallet_name, keypool * output_types, transactions, imported_privs * 3 + address))

    def read_dump(self, filename):
        dump = OrderedDict()
        with open(filename, "r") as f:
            for row in f:
                row = row.strip()
                key, value = row.split(',')
                dump[key] = value
        return dump

    def assert_is_sqlite(self, filename):
        with open(filename, 'rb') as f:
            file_magic = f.read(16)
            assert_equal(file_magic, b'SQLite format 3\x00')

    def write_dump(self, dump, filename, magic=None, skip_checksum=False):
        if magic is None:
            magic = "BITCOIN_CORE_WALLET_DUMP"
        with open(filename, "w") as f:
            row = ",".join([magic, dump[magic]]) + "\n"
            f.write(row)
            for k, v in dump.items():
                if k == magic or k == "checksum":
                    continue
                row = ",".join([k, v]) + "\n"
                f.write(row)
            if not skip_checksum:
                row = ",".join(["checksum", dump["checksum"]]) + "\n"
                f.write(row)

    def do_tool_createfromdump(self, wallet_name, dumpfile):
        dumppath = self.nodes[0].datadir_path / dumpfile
        rt_dumppath = self.nodes[0].datadir_path / "rt-{}.dump".format(wallet_name)

        args = ["-wallet={}".format(wallet_name),
                "-dumpfile={}".format(dumppath)]
        args.append("createfromdump")

        load_output = ""
        self.assert_tool_output(load_output, *args)
        assert (self.nodes[0].wallets_path / wallet_name).is_dir()

        self.assert_tool_output("The dumpfile may contain private keys. To ensure the safety of your Bitcoin, do not share the dumpfile.\n", '-wallet={}'.format(wallet_name), '-dumpfile={}'.format(rt_dumppath), 'dump')

        wallet_dat = self.nodes[0].wallets_path / wallet_name / "wallet.dat"
        self.assert_is_sqlite(wallet_dat)

    def test_invalid_tool_commands_and_args(self):
        self.log.info('Testing that various invalid commands raise with specific error messages')
        self.assert_raises_tool_error("Error parsing command line arguments: Invalid command 'foo'", 'foo')
        # `bitcoin-wallet help` raises an error. Use `bitcoin-wallet -help`.
        self.assert_raises_tool_error("Error parsing command line arguments: Invalid command 'help'", 'help')
        self.assert_raises_tool_error('Error: Additional arguments provided (create). Methods do not take arguments. Please refer to `-help`.', 'info', 'create')
        self.assert_raises_tool_error('Error parsing command line arguments: Invalid parameter -foo', '-foo')
        self.assert_raises_tool_error('No method provided. Run `bitcoin-wallet -help` for valid methods.')
        self.assert_raises_tool_error('Wallet name must be provided when creating a new wallet.', 'create')
        self.assert_raises_tool_error('Wallet name must be provided when creating a new wallet.', 'createfromdump')
        error = f"SQLiteDatabase: Unable to obtain an exclusive lock on the database, is it being used by another instance of {self.config['environment']['CLIENT_NAME']}?"
        self.assert_raises_tool_error(
            error,
            '-wallet=' + self.default_wallet_name,
            'info',
        )
        path = self.nodes[0].wallets_path / "nonexistent.dat"
        self.assert_raises_tool_error("Failed to load database path '{}'. Path does not exist.".format(path), '-wallet=nonexistent.dat', 'info')

    def test_tool_wallet_info(self):
        # Stop the node to close the wallet to call the info command.
        self.stop_node(0)
        self.log.info('Calling wallet tool info, testing output')
        #
        # TODO: Wallet tool info should work with wallet file permissions set to
        # read-only without raising:
        # "Error loading wallet.dat. Is wallet being used by another process?"
        # The following lines should be uncommented and the tests still succeed:
        #
        # self.log.debug('Setting wallet file permissions to 400 (read-only)')
        # os.chmod(self.wallet_path, stat.S_IRUSR)
        # assert self.wallet_permissions() in ['400', '666'] # Sanity check. 666 on Windows.
        # shasum_before = self.wallet_shasum()
        timestamp_before = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp before calling info: {}'.format(timestamp_before))
        out = self.get_expected_info_output(imported_privs=1)
        self.assert_tool_output(out, '-wallet=' + self.default_wallet_name, 'info')
        timestamp_after = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp after calling info: {}'.format(timestamp_after))
        self.log_wallet_timestamp_comparison(timestamp_before, timestamp_after)
        self.log.debug('Setting wallet file permissions back to 600 (read/write)')
        os.chmod(self.wallet_path, stat.S_IRUSR | stat.S_IWUSR)
        assert self.wallet_permissions() in ['600', '666']  # Sanity check. 666 on Windows.
        #
        # TODO: Wallet tool info should not write to the wallet file.
        # The following lines should be uncommented and the tests still succeed:
        #
        # assert_equal(timestamp_before, timestamp_after)
        # shasum_after = self.wallet_shasum()
        # assert_equal(shasum_before, shasum_after)
        # self.log.debug('Wallet file shasum unchanged\n')

    def test_tool_wallet_info_after_transaction(self):
        """
        Mutate the wallet with a transaction to verify that the info command
        output changes accordingly.
        """
        self.start_node(0)
        self.log.info('Generating transaction to mutate wallet')
        self.generate(self.nodes[0], 1)
        self.stop_node(0)

        self.log.info('Calling wallet tool info after generating a transaction, testing output')
        shasum_before = self.wallet_shasum()
        timestamp_before = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp before calling info: {}'.format(timestamp_before))
        out = self.get_expected_info_output(transactions=1, imported_privs=1)
        self.assert_tool_output(out, '-wallet=' + self.default_wallet_name, 'info')
        shasum_after = self.wallet_shasum()
        timestamp_after = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp after calling info: {}'.format(timestamp_after))
        self.log_wallet_timestamp_comparison(timestamp_before, timestamp_after)
        #
        # TODO: Wallet tool info should not write to the wallet file.
        # This assertion should be uncommented and succeed:
        # assert_equal(timestamp_before, timestamp_after)
        assert_equal(shasum_before, shasum_after)
        self.log.debug('Wallet file shasum unchanged\n')

    def test_tool_wallet_create_on_existing_wallet(self):
        self.log.info('Calling wallet tool create on an existing wallet, testing output')
        shasum_before = self.wallet_shasum()
        timestamp_before = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp before calling create: {}'.format(timestamp_before))
        out = "Topping up keypool...\n" + self.get_expected_info_output(name="foo", keypool=2000)
        self.assert_tool_output(out, '-wallet=foo', 'create')
        shasum_after = self.wallet_shasum()
        timestamp_after = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp after calling create: {}'.format(timestamp_after))
        self.log_wallet_timestamp_comparison(timestamp_before, timestamp_after)
        assert_equal(timestamp_before, timestamp_after)
        assert_equal(shasum_before, shasum_after)
        self.log.debug('Wallet file shasum unchanged\n')

    def test_getwalletinfo_on_different_wallet(self):
        self.log.info('Starting node with arg -wallet=foo')
        self.start_node(0, ['-nowallet', '-wallet=foo'])

        self.log.info('Calling getwalletinfo on a different wallet ("foo"), testing output')
        shasum_before = self.wallet_shasum()
        timestamp_before = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp before calling getwalletinfo: {}'.format(timestamp_before))
        out = self.nodes[0].getwalletinfo()
        self.stop_node(0)

        shasum_after = self.wallet_shasum()
        timestamp_after = self.wallet_timestamp()
        self.log.debug('Wallet file timestamp after calling getwalletinfo: {}'.format(timestamp_after))

        assert_equal(0, out['txcount'])
        assert_equal(4000, out['keypoolsize'])
        assert_equal(4000, out['keypoolsize_hd_internal'])

        self.log_wallet_timestamp_comparison(timestamp_before, timestamp_after)
        assert_equal(timestamp_before, timestamp_after)
        assert_equal(shasum_after, shasum_before)
        self.log.debug('Wallet file shasum unchanged\n')

    def test_dump_createfromdump(self):
        self.start_node(0)
        self.nodes[0].createwallet("todump")
        file_format = self.nodes[0].get_wallet_rpc("todump").getwalletinfo()["format"]
        self.nodes[0].createwallet("todump2")
        self.stop_node(0)

        self.log.info('Checking dump arguments')
        self.assert_raises_tool_error('No dump file provided. To use dump, -dumpfile=<filename> must be provided.', '-wallet=todump', 'dump')

        self.log.info('Checking basic dump')
        wallet_dump = self.nodes[0].datadir_path / "wallet.dump"
        self.assert_tool_output('The dumpfile may contain private keys. To ensure the safety of your Bitcoin, do not share the dumpfile.\n', '-wallet=todump', '-dumpfile={}'.format(wallet_dump), 'dump')

        dump_data = self.read_dump(wallet_dump)
        orig_dump = dump_data.copy()
        # Check the dump magic
        assert_equal(dump_data['BITCOIN_CORE_WALLET_DUMP'], '1')
        # Check the file format
        assert_equal(dump_data["format"], file_format)

        self.log.info('Checking that a dumpfile cannot be overwritten')
        self.assert_raises_tool_error('File {} already exists. If you are sure this is what you want, move it out of the way first.'.format(wallet_dump),  '-wallet=todump2', '-dumpfile={}'.format(wallet_dump), 'dump')

        self.log.info('Checking createfromdump arguments')
        self.assert_raises_tool_error('No dump file provided. To use createfromdump, -dumpfile=<filename> must be provided.', '-wallet=todump', 'createfromdump')
        non_exist_dump = self.nodes[0].datadir_path / "wallet.nodump"
        self.assert_raises_tool_error('Dump file {} does not exist.'.format(non_exist_dump), '-wallet=todump', '-dumpfile={}'.format(non_exist_dump), 'createfromdump')
        wallet_path = self.nodes[0].wallets_path / "todump2"
        self.assert_raises_tool_error('Failed to create database path \'{}\'. Database already exists.'.format(wallet_path), '-wallet=todump2', '-dumpfile={}'.format(wallet_dump), 'createfromdump')
        self.assert_raises_tool_error("Invalid parameter -descriptors", '-descriptors', '-wallet=todump2', '-dumpfile={}'.format(wallet_dump), 'createfromdump')

        self.log.info('Checking createfromdump')
        self.do_tool_createfromdump("load", "wallet.dump")

        self.log.info('Checking createfromdump handling of magic and versions')
        bad_ver_wallet_dump = self.nodes[0].datadir_path / "wallet-bad_ver1.dump"
        dump_data["BITCOIN_CORE_WALLET_DUMP"] = "0"
        self.write_dump(dump_data, bad_ver_wallet_dump)
        self.assert_raises_tool_error('Error: Dumpfile version is not supported. This version of bitcoin-wallet only supports version 1 dumpfiles. Got dumpfile with version 0', '-wallet=badload', '-dumpfile={}'.format(bad_ver_wallet_dump), 'createfromdump')
        assert not (self.nodes[0].wallets_path / "badload").is_dir()
        bad_ver_wallet_dump = self.nodes[0].datadir_path / "wallet-bad_ver2.dump"
        dump_data["BITCOIN_CORE_WALLET_DUMP"] = "2"
        self.write_dump(dump_data, bad_ver_wallet_dump)
        self.assert_raises_tool_error('Error: Dumpfile version is not supported. This version of bitcoin-wallet only supports version 1 dumpfiles. Got dumpfile with version 2', '-wallet=badload', '-dumpfile={}'.format(bad_ver_wallet_dump), 'createfromdump')
        assert not (self.nodes[0].wallets_path / "badload").is_dir()
        bad_magic_wallet_dump = self.nodes[0].datadir_path / "wallet-bad_magic.dump"
        del dump_data["BITCOIN_CORE_WALLET_DUMP"]
        dump_data["not_the_right_magic"] = "1"
        self.write_dump(dump_data, bad_magic_wallet_dump, "not_the_right_magic")
        self.assert_raises_tool_error('Error: Dumpfile identifier record is incorrect. Got "not_the_right_magic", expected "BITCOIN_CORE_WALLET_DUMP".', '-wallet=badload', '-dumpfile={}'.format(bad_magic_wallet_dump), 'createfromdump')
        assert not (self.nodes[0].wallets_path / "badload").is_dir()

        self.log.info('Checking createfromdump handling of checksums')
        bad_sum_wallet_dump = self.nodes[0].datadir_path / "wallet-bad_sum1.dump"
        dump_data = orig_dump.copy()
        checksum = dump_data["checksum"]
        dump_data["checksum"] = "1" * 64
        self.write_dump(dump_data, bad_sum_wallet_dump)
        self.assert_raises_tool_error('Error: Dumpfile checksum does not match. Computed {}, expected {}'.format(checksum, "1" * 64), '-wallet=bad', '-dumpfile={}'.format(bad_sum_wallet_dump), 'createfromdump')
        assert not (self.nodes[0].wallets_path / "badload").is_dir()
        bad_sum_wallet_dump = self.nodes[0].datadir_path / "wallet-bad_sum2.dump"
        del dump_data["checksum"]
        self.write_dump(dump_data, bad_sum_wallet_dump, skip_checksum=True)
        self.assert_raises_tool_error('Error: Missing checksum', '-wallet=badload', '-dumpfile={}'.format(bad_sum_wallet_dump), 'createfromdump')
        assert not (self.nodes[0].wallets_path / "badload").is_dir()
        bad_sum_wallet_dump = self.nodes[0].datadir_path / "wallet-bad_sum3.dump"
        dump_data["checksum"] = "2" * 10
        self.write_dump(dump_data, bad_sum_wallet_dump)
        self.assert_raises_tool_error('Error: Checksum is not the correct size', '-wallet=badload', '-dumpfile={}'.format(bad_sum_wallet_dump), 'createfromdump')
        assert not (self.nodes[0].wallets_path / "badload").is_dir()
        dump_data["checksum"] = "3" * 66
        self.write_dump(dump_data, bad_sum_wallet_dump)
        self.assert_raises_tool_error('Error: Checksum is not the correct size', '-wallet=badload', '-dumpfile={}'.format(bad_sum_wallet_dump), 'createfromdump')
        assert not (self.nodes[0].wallets_path / "badload").is_dir()

    def test_chainless_conflicts(self):
        self.log.info("Test wallet tool when wallet contains conflicting transactions")
        self.restart_node(0)
        self.generate(self.nodes[0], 101)

        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        self.nodes[0].createwallet("conflicts")
        wallet = self.nodes[0].get_wallet_rpc("conflicts")
        def_wallet.sendtoaddress(wallet.getnewaddress(), 10)
        self.generate(self.nodes[0], 1)

        # parent tx
        parent_txid = wallet.sendtoaddress(wallet.getnewaddress(), 9)
        parent_txid_bytes = bytes.fromhex(parent_txid)[::-1]
        conflict_utxo = wallet.gettransaction(txid=parent_txid, verbose=True)["decoded"]["vin"][0]

        # The specific assertion in MarkConflicted being tested requires that the parent tx is already loaded
        # by the time the child tx is loaded. Since transactions end up being loaded in txid order due to how both
        # and sqlite store things, we can just grind the child tx until it has a txid that is greater than the parent's.
        locktime = 500000000 # Use locktime as nonce, starting at unix timestamp minimum
        addr = wallet.getnewaddress()
        while True:
            child_send_res = wallet.send(outputs=[{addr: 8}], add_to_wallet=False, locktime=locktime)
            child_txid = child_send_res["txid"]
            child_txid_bytes = bytes.fromhex(child_txid)[::-1]
            if (child_txid_bytes > parent_txid_bytes):
                wallet.sendrawtransaction(child_send_res["hex"])
                break
            locktime += 1

        # conflict with parent
        conflict_unsigned = self.nodes[0].createrawtransaction(inputs=[conflict_utxo], outputs=[{wallet.getnewaddress(): 9.9999}])
        conflict_signed = wallet.signrawtransactionwithwallet(conflict_unsigned)["hex"]
        conflict_txid = self.nodes[0].sendrawtransaction(conflict_signed)
        self.generate(self.nodes[0], 1)
        assert_equal(wallet.gettransaction(txid=parent_txid)["confirmations"], -1)
        assert_equal(wallet.gettransaction(txid=child_txid)["confirmations"], -1)
        assert_equal(wallet.gettransaction(txid=conflict_txid)["confirmations"], 1)

        self.stop_node(0)

        # Wallet tool should successfully give info for this wallet
        expected_output = textwrap.dedent('''\
            Wallet info
            ===========
            Name: conflicts
            Format: sqlite
            Descriptors: yes
            Encrypted: no
            HD (hd seed available): yes
            Keypool Size: 8
            Transactions: 4
            Address Book: 4
        ''')
        self.assert_tool_output(expected_output, "-wallet=conflicts", "info")

    def test_dump_very_large_records(self):
        self.log.info("Test that wallets with large records are successfully dumped")

        self.start_node(0)
        self.nodes[0].createwallet("bigrecords")
        wallet = self.nodes[0].get_wallet_rpc("bigrecords")

        # Both BDB and sqlite have maximum page sizes of 65536 bytes, with defaults of 4096
        # When a record exceeds some size threshold, both BDB and SQLite will store the data
        # in one or more overflow pages. We want to make sure that our tooling can dump such
        # records, even when they span multiple pages. To make a large record, we just need
        # to make a very big transaction.
        self.generate(self.nodes[0], 101)
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        outputs = {}
        for i in range(500):
            outputs[wallet.getnewaddress(address_type="p2sh-segwit")] = 0.01
        def_wallet.sendmany(amounts=outputs)
        self.generate(self.nodes[0], 1)
        send_res = wallet.sendall([def_wallet.getnewaddress()])
        self.generate(self.nodes[0], 1)
        assert_equal(send_res["complete"], True)
        tx = wallet.gettransaction(txid=send_res["txid"], verbose=True)
        assert_greater_than(tx["decoded"]["size"], 70000)

        self.stop_node(0)

        wallet_dump = self.nodes[0].datadir_path / "bigrecords.dump"
        self.assert_tool_output("The dumpfile may contain private keys. To ensure the safety of your Bitcoin, do not share the dumpfile.\n", "-wallet=bigrecords", f"-dumpfile={wallet_dump}", "dump")
        dump = self.read_dump(wallet_dump)
        for k,v in dump.items():
            if tx["hex"] in v:
                break
        else:
            assert False, "Big transaction was not found in wallet dump"

    def test_no_create_legacy(self):
        self.log.info("Test that legacy wallets cannot be created")

        self.assert_raises_tool_error("Invalid parameter -legacy", "-wallet=legacy", "-legacy", "create")
        assert not (self.nodes[0].wallets_path / "legacy").exists()
        self.assert_raises_tool_error("Invalid parameter -descriptors", "-wallet=legacy", "-descriptors=false", "create")
        assert not (self.nodes[0].wallets_path / "legacy").exists()

    def test_no_create_unnamed(self):
        self.log.info("Test that unnamed (default) wallets cannot be created")

        self.assert_raises_tool_error("Wallet name cannot be empty", "-wallet=", "create")
        assert not (self.nodes[0].wallets_path / "wallet.dat").exists()

        self.assert_raises_tool_error("Wallet name cannot be empty", "-wallet=", "-dumpfile=wallet.dump", "createfromdump")
        assert not (self.nodes[0].wallets_path / "wallet.dat").exists()

    def test_encrypt_descriptor(self):
        """Test encryptdescriptor command."""
        self.log.info("Test encryptdescriptor")

        # Create a test wallet to get a descriptor from listdescriptors
        self.start_node(0)
        wallet_name = "backup_test_wallet"
        self.nodes[0].createwallet(wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)

        # Pick one descriptor to encrypt
        original_descriptors = wallet.listdescriptors()["descriptors"]
        chosen_desc = original_descriptors[0]["desc"]

        self.nodes[0].unloadwallet(wallet_name)
        self.stop_node(0)

        # Encrypt the chosen descriptor
        self.log.info("Encrypting descriptor...")
        p = self.bitcoin_wallet_process(f"-descriptor={chosen_desc}", "encryptdescriptor")
        backup_output, stderr = p.communicate()
        assert_equal(p.poll(), 0)
        assert_equal(stderr, "")
        backup_base64 = backup_output.strip()

        # Verify it's base64 and starts with expected magic when decoded
        import base64
        backup_bytes = base64.b64decode(backup_base64)
        assert backup_bytes[:3] == b"BIP", f"Expected magic 'BIP', got: {backup_bytes[:3]}"

        # Test raw binary backup file roundtrip via -backupfile
        self.log.info("Testing raw binary backup via -backupfile...")
        backup_file = self.nodes[0].datadir_path / "backup.bin"
        assert not backup_file.exists()

        p = self.bitcoin_wallet_process(f"-descriptor={chosen_desc}", f"-backupfile={backup_file}", "encryptdescriptor")
        _, stderr = p.communicate()
        assert_equal(p.poll(), 0)
        assert_equal(stderr, "")
        assert backup_file.exists()

        # Verify file is raw binary (starts with magic, not base64)
        raw_bytes = backup_file.read_bytes()
        assert len(raw_bytes) > 0
        assert_equal(raw_bytes[:3], b"BIP")

        # Refuse to overwrite existing file
        self.assert_raises_tool_error(
            "already exists",
            f"-descriptor={chosen_desc}", f"-backupfile={backup_file}", "encryptdescriptor",
        )

        backup_file.unlink()

        self.log.info("encryptdescriptor test passed!")

    def _setup_for_encrypted_backup_errors(self, suffix):
        """Get a real descriptor + xpub from a fresh wallet, plus a real backup."""
        import re
        self.start_node(0)
        wallet_name = f"err_src_wallet_{suffix}"
        self.nodes[0].createwallet(wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)
        chosen_desc = wallet.listdescriptors()["descriptors"][0]["desc"]
        xpub = re.search(r'tpub[A-Za-z0-9]+', chosen_desc).group(0)
        self.nodes[0].unloadwallet(wallet_name)
        self.stop_node(0)
        p = self.bitcoin_wallet_process(f"-descriptor={chosen_desc}", "encryptdescriptor")
        backup_output, _ = p.communicate()
        assert_equal(p.poll(), 0)
        return chosen_desc, xpub, backup_output.strip()

    def test_encrypt_descriptor_errors(self):
        """Test wallet-tool encryptdescriptor error paths."""
        self.log.info("Test wallet-tool encryptdescriptor error cases")
        chosen_desc, _, _ = self._setup_for_encrypted_backup_errors("enc")

        # Missing -descriptor
        self.assert_raises_tool_error("Descriptor string must be provided", "encryptdescriptor")
        # Invalid/unparseable descriptor
        self.assert_raises_tool_error("Invalid descriptor",
                                     "-descriptor=this is not a descriptor", "encryptdescriptor")
        # File already exists
        backup_file = self.nodes[0].datadir_path / "err_existing.bin"
        backup_file.write_bytes(b"placeholder")
        self.assert_raises_tool_error(
            "already exists",
            f"-descriptor={chosen_desc}", f"-backupfile={backup_file}", "encryptdescriptor",
        )
        backup_file.unlink()

        self.log.info("wallet-tool encryptdescriptor error cases passed!")

    def test_decrypt_descriptor(self):
        """Test decryptdescriptor command."""
        self.log.info("Test decryptdescriptor")

        # Create a test wallet to get a descriptor
        self.start_node(0)
        wallet_name = "decrypt_test_wallet"
        self.nodes[0].createwallet(wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)

        # Pick one descriptor to encrypt then decrypt
        original_descriptors = wallet.listdescriptors()["descriptors"]
        chosen_desc = original_descriptors[0]["desc"]

        # Extract an xpub from the descriptor for decryption
        import re
        xpub_match = re.search(r'tpub[A-Za-z0-9]+', chosen_desc)
        assert xpub_match, "Could not find tpub in descriptor"
        xpub_for_decrypt = xpub_match.group(0)

        self.nodes[0].unloadwallet(wallet_name)
        self.stop_node(0)

        # Encrypt
        self.log.info("Encrypting descriptor...")
        p = self.bitcoin_wallet_process(f"-descriptor={chosen_desc}", "encryptdescriptor")
        backup_output, stderr = p.communicate()
        assert_equal(p.poll(), 0)
        backup_base64 = backup_output.strip()

        # Decrypt using xpub
        self.log.info("Decrypting backup using xpub...")
        p = self.bitcoin_wallet_process(f"-xpub={xpub_for_decrypt}", "decryptdescriptor")
        decrypted_output, stderr = p.communicate(input=backup_base64)
        assert_equal(p.poll(), 0)

        # Output should be the raw descriptor string
        decrypted_desc = decrypted_output.strip()
        assert_equal(decrypted_desc, chosen_desc)

        # Test decrypt from -backupfile
        self.log.info("Testing decrypt from -backupfile...")
        backup_file = self.nodes[0].datadir_path / "decrypt_test.bin"
        p = self.bitcoin_wallet_process(f"-descriptor={chosen_desc}", f"-backupfile={backup_file}", "encryptdescriptor")
        p.communicate()
        assert_equal(p.poll(), 0)

        p = self.bitcoin_wallet_process(f"-xpub={xpub_for_decrypt}", f"-backupfile={backup_file}", "decryptdescriptor")
        decrypted_output, stderr = p.communicate()
        assert_equal(p.poll(), 0)
        assert_equal(decrypted_output.strip(), chosen_desc)

        backup_file.unlink()

        self.log.info("decryptdescriptor test passed!")

    def test_decrypt_descriptor_xpub_formats(self):
        """Verify wallet-tool decryptdescriptor accepts each xpub form."""
        import re
        self.log.info("Test wallet-tool decryptdescriptor xpub format coverage")

        self.start_node(0)
        wallet_name = "xpub_fmt_src_wallet"
        self.nodes[0].createwallet(wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)
        chosen_desc = wallet.listdescriptors()["descriptors"][0]["desc"]
        self.nodes[0].unloadwallet(wallet_name)
        self.stop_node(0)

        m = re.match(r'^[a-z]+\(\[(?P<origin>[^\]]+)\](?P<xpub>[tx]pub[A-Za-z0-9]+)(?P<deriv>/[^)]*)?\)', chosen_desc)
        assert m is not None, f"Failed to parse chosen_desc: {chosen_desc}"
        origin = m.group("origin")
        xpub = m.group("xpub")
        deriv = m.group("deriv") or "/0/*"

        forms = {
            "bare": xpub,
            "with_origin": f"[{origin}]{xpub}",
            "with_deriv": f"{xpub}{deriv}",
            "with_origin_and_deriv": f"[{origin}]{xpub}{deriv}",
            "multipath": f"{xpub}/<0;1>/*",
        }

        p = self.bitcoin_wallet_process(f"-descriptor={chosen_desc}", "encryptdescriptor")
        backup_output, _ = p.communicate()
        assert_equal(p.poll(), 0)
        backup_base64 = backup_output.strip()

        for label, x in forms.items():
            p = self.bitcoin_wallet_process(f"-xpub={x}", "decryptdescriptor")
            out, _ = p.communicate(input=backup_base64)
            assert_equal(p.poll(), 0)
            assert_equal(out.strip(), chosen_desc)
            self.log.info(f"  decryptdescriptor with {label} xpub: OK")

    def test_decrypt_descriptor_errors(self):
        """Test wallet-tool decryptdescriptor error paths."""
        self.log.info("Test wallet-tool decryptdescriptor error cases")
        _, xpub, backup_base64 = self._setup_for_encrypted_backup_errors("dec")
        wrong_xpub = "tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x"

        # Missing -xpub
        p = self.bitcoin_wallet_process("decryptdescriptor")
        _, stderr = p.communicate(input=backup_base64)
        assert_equal(p.poll(), 1)
        assert "Extended public key must be provided" in stderr

        # Wrong xpub
        p = self.bitcoin_wallet_process(f"-xpub={wrong_xpub}", "decryptdescriptor")
        _, stderr = p.communicate(input=backup_base64)
        assert_equal(p.poll(), 1)
        assert "Failed to decrypt" in stderr

        # Empty stdin
        p = self.bitcoin_wallet_process(f"-xpub={xpub}", "decryptdescriptor")
        _, stderr = p.communicate(input="")
        assert_equal(p.poll(), 1)
        assert "No backup data provided on stdin" in stderr

        # Garbage stdin (not base64)
        p = self.bitcoin_wallet_process(f"-xpub={xpub}", "decryptdescriptor")
        _, stderr = p.communicate(input="not-valid-base64!!!")
        assert_equal(p.poll(), 1)
        assert stderr.strip() != ""

        self.log.info("wallet-tool decryptdescriptor error cases passed!")

    def test_import_encrypted_descriptor(self):
        """Test importencrypteddescriptor command."""
        self.log.info("Test importencrypteddescriptor")

        # Create a source wallet and pick a descriptor
        self.start_node(0)
        src_wallet_name = "import_src_wallet"
        self.nodes[0].createwallet(src_wallet_name)
        src_wallet = self.nodes[0].get_wallet_rpc(src_wallet_name)

        original_descriptors = src_wallet.listdescriptors()["descriptors"]
        chosen_desc = original_descriptors[0]["desc"]

        import re
        xpub_match = re.search(r'tpub[A-Za-z0-9]+', chosen_desc)
        assert xpub_match, "Could not find tpub in descriptor"
        xpub_for_decrypt = xpub_match.group(0)

        self.nodes[0].unloadwallet(src_wallet_name)
        self.stop_node(0)

        # Encrypt the descriptor
        p = self.bitcoin_wallet_process(f"-descriptor={chosen_desc}", "encryptdescriptor")
        backup_output, stderr = p.communicate()
        assert_equal(p.poll(), 0)
        backup_base64 = backup_output.strip()

        # Create a blank wallet to import into
        import_wallet_name = "import_dest_wallet"
        self.bitcoin_wallet_process(f"-wallet={import_wallet_name}", "create").communicate()

        # Import via importencrypteddescriptor
        self.log.info("Importing encrypted descriptor into wallet...")
        p = self.bitcoin_wallet_process(
            f"-wallet={import_wallet_name}", f"-xpub={xpub_for_decrypt}",
            "importencrypteddescriptor")
        import_output, stderr = p.communicate(input=backup_base64)
        if p.poll() != 0:
            self.log.error(f"importencrypteddescriptor failed: stderr={stderr}, stdout={import_output}")
        assert_equal(p.poll(), 0)
        assert "imported successfully" in import_output

        # Verify the descriptor was imported
        self.start_node(0)
        self.nodes[0].loadwallet(import_wallet_name)
        imported_wallet = self.nodes[0].get_wallet_rpc(import_wallet_name)
        imported_descriptors = imported_wallet.listdescriptors()["descriptors"]
        imported_desc_strs = [d["desc"] for d in imported_descriptors]

        assert chosen_desc in imported_desc_strs, \
            f"Descriptor {chosen_desc} not found in imported wallet. Got: {imported_desc_strs}"

        self.nodes[0].unloadwallet(import_wallet_name)
        self.stop_node(0)

        self.log.info("importencrypteddescriptor test passed!")

    def test_import_encrypted_descriptor_errors(self):
        """Test wallet-tool importencrypteddescriptor error paths."""
        self.log.info("Test wallet-tool importencrypteddescriptor error cases")
        _, xpub, backup_base64 = self._setup_for_encrypted_backup_errors("imp")

        # Missing -wallet
        p = self.bitcoin_wallet_process(f"-xpub={xpub}", "importencrypteddescriptor")
        _, stderr = p.communicate(input=backup_base64)
        assert_equal(p.poll(), 1)
        assert "Wallet name must be provided" in stderr

        # Missing -xpub
        p = self.bitcoin_wallet_process("-wallet=nonexistent_wallet", "importencrypteddescriptor")
        _, stderr = p.communicate(input=backup_base64)
        assert_equal(p.poll(), 1)
        assert "Extended public key must be provided" in stderr

        # Nonexistent wallet
        p = self.bitcoin_wallet_process(
            "-wallet=nonexistent_wallet_xyz", f"-xpub={xpub}", "importencrypteddescriptor")
        _, stderr = p.communicate(input=backup_base64)
        assert_equal(p.poll(), 1)
        assert stderr.strip() != ""

        self.log.info("wallet-tool importencrypteddescriptor error cases passed!")

    def run_test(self):
        self.wallet_path = self.nodes[0].wallets_path / self.default_wallet_name / self.wallet_data_filename
        self.test_invalid_tool_commands_and_args()
        # Warning: The following tests are order-dependent.
        self.test_tool_wallet_info()
        self.test_tool_wallet_info_after_transaction()
        self.test_tool_wallet_create_on_existing_wallet()
        self.test_getwalletinfo_on_different_wallet()
        self.test_dump_createfromdump()
        self.test_chainless_conflicts()
        self.test_dump_very_large_records()
        self.test_no_create_legacy()
        self.test_no_create_unnamed()
        self.test_encrypt_descriptor()
        self.test_encrypt_descriptor_errors()
        self.test_decrypt_descriptor()
        self.test_decrypt_descriptor_xpub_formats()
        self.test_decrypt_descriptor_errors()
        self.test_import_encrypted_descriptor()
        self.test_import_encrypted_descriptor_errors()


if __name__ == '__main__':
    ToolWalletTest(__file__).main()
