#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the importdescriptors RPC.

Test importdescriptors by generating keys on node0, importing the corresponding
descriptors on node1 and then testing the address info for the different address
variants.

- `get_generate_key()` is called to generate keys and return the privkeys,
  pubkeys and all variants of scriptPubKey and address.
- `test_importdesc()` is called to send an importdescriptors call to node1, test
  success, and (if unsuccessful) test the error code and error message returned.
- `test_address()` is called to call getaddressinfo for an address on node1
  and test the values returned."""

import concurrent.futures
import time

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import (
    get_generate_key,
    test_address,
)

class ImportDescriptorsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True
        self.extra_args = [["-addresstype=legacy"],
                           ["-addresstype=bech32", "-keypool=5"]
                          ]
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def test_importdesc(self, req, success, error_code=None, error_message=None, warnings=None, wallet=None):
        """Run importdescriptors and assert success"""
        if warnings is None:
            warnings = []
        wrpc = self.nodes[1].get_wallet_rpc('w1')
        if wallet is not None:
            wrpc = wallet

        result = wrpc.importdescriptors([req])
        observed_warnings = []
        if 'warnings' in result[0]:
            observed_warnings = result[0]['warnings']
        assert_equal("\n".join(sorted(warnings)), "\n".join(sorted(observed_warnings)))
        assert_equal(result[0]['success'], success)
        if error_code is not None:
            assert_equal(result[0]['error']['code'], error_code)
            assert_equal(result[0]['error']['message'], error_message)

    def run_test(self):
        self.log.info('Setting up wallets')
        self.nodes[0].createwallet(wallet_name='w0', disable_private_keys=False, descriptors=True)
        w0 = self.nodes[0].get_wallet_rpc('w0')

        self.nodes[1].createwallet(wallet_name='w1', disable_private_keys=True, blank=True, descriptors=True)
        w1 = self.nodes[1].get_wallet_rpc('w1')
        assert_equal(w1.getwalletinfo()['keypoolsize'], 0)

        self.nodes[1].createwallet(wallet_name="wpriv", disable_private_keys=False, blank=True, descriptors=True)
        wpriv = self.nodes[1].get_wallet_rpc("wpriv")
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 0)

        self.log.info('Mining coins')
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 1, w0.getnewaddress())

        # RPC importdescriptors -----------------------------------------------

        # # Test import fails if no descriptor present
        self.log.info("Import should fail if a descriptor is not provided")
        self.test_importdesc({"timestamp": "now"},
                             success=False,
                             error_code=-8,
                             error_message='Descriptor not found.')

        # # Test importing of a P2PKH descriptor
        key = get_generate_key()
        self.log.info("Should import a p2pkh descriptor")
        import_request = {"desc": descsum_create("pkh(" + key.pubkey + ")"),
                 "timestamp": "now",
                 "label": "Descriptor import test"}
        self.test_importdesc(import_request, success=True)
        test_address(w1,
                     key.p2pkh_addr,
                     solvable=True,
                     ismine=True,
                     labels=["Descriptor import test"])
        assert_equal(w1.getwalletinfo()['keypoolsize'], 0)

        self.log.info("Test can import same descriptor with public key twice")
        self.test_importdesc(import_request, success=True)

        self.log.info("Test can update descriptor label")
        self.test_importdesc({**import_request, "label": "Updated label"}, success=True)
        test_address(w1, key.p2pkh_addr, solvable=True, ismine=True, labels=["Updated label"])

        self.log.info("Internal addresses cannot have labels")
        self.test_importdesc({**import_request, "internal": True},
                             success=False,
                             error_code=-8,
                             error_message="Internal addresses should not have a label")

        self.log.info("Internal addresses should be detected as such")
        key = get_generate_key()
        self.test_importdesc({"desc": descsum_create("pkh(" + key.pubkey + ")"),
                              "timestamp": "now",
                              "internal": True},
                             success=True)
        info = w1.getaddressinfo(key.p2pkh_addr)
        assert_equal(info["ismine"], True)
        assert_equal(info["ischange"], True)

        # # Test importing of a P2SH-P2WPKH descriptor
        key = get_generate_key()
        self.log.info("Should not import a p2sh-p2wpkh descriptor without checksum")
        self.test_importdesc({"desc": "sh(wpkh(" + key.pubkey + "))",
                              "timestamp": "now"
                              },
                             success=False,
                             error_code=-5,
                             error_message="Missing checksum")

        self.log.info("Should not import a p2sh-p2wpkh descriptor that has range specified")
        self.test_importdesc({"desc": descsum_create("sh(wpkh(" + key.pubkey + "))"),
                               "timestamp": "now",
                               "range": 1,
                              },
                              success=False,
                              error_code=-8,
                              error_message="Range should not be specified for an un-ranged descriptor")

        self.log.info("Should not import a p2sh-p2wpkh descriptor and have it set to active")
        self.test_importdesc({"desc": descsum_create("sh(wpkh(" + key.pubkey + "))"),
                               "timestamp": "now",
                               "active": True,
                              },
                              success=False,
                              error_code=-8,
                              error_message="Active descriptors must be ranged")

        self.log.info("Should import a (non-active) p2sh-p2wpkh descriptor")
        self.test_importdesc({"desc": descsum_create("sh(wpkh(" + key.pubkey + "))"),
                               "timestamp": "now",
                               "active": False,
                              },
                              success=True)
        assert_equal(w1.getwalletinfo()['keypoolsize'], 0)

        test_address(w1,
                     key.p2sh_p2wpkh_addr,
                     ismine=True,
                     solvable=True)

        # Check persistence of data and that loading works correctly
        w1.unloadwallet()
        self.nodes[1].loadwallet('w1')
        test_address(w1,
                     key.p2sh_p2wpkh_addr,
                     ismine=True,
                     solvable=True)

        # # Test importing of a multisig descriptor
        key1 = get_generate_key()
        key2 = get_generate_key()
        self.log.info("Should import a 1-of-2 bare multisig from descriptor")
        self.test_importdesc({"desc": descsum_create("multi(1," + key1.pubkey + "," + key2.pubkey + ")"),
                              "timestamp": "now"},
                             success=True)
        self.log.info("Should not treat individual keys from the imported bare multisig as watchonly")
        test_address(w1,
                     key1.p2pkh_addr,
                     ismine=False)

        # # Test ranged descriptors
        xpriv = "tprv8ZgxMBicQKsPeuVhWwi6wuMQGfPKi9Li5GtX35jVNknACgqe3CY4g5xgkfDDJcmtF7o1QnxWDRYw4H5P26PXq7sbcUkEqeR4fg3Kxp2tigg"
        xpub = "tpubD6NzVbkrYhZ4YNXVQbNhMK1WqguFsUXceaVJKbmno2aZ3B6QfbMeraaYvnBSGpV3vxLyTTK9DYT1yoEck4XUScMzXoQ2U2oSmE2JyMedq3H"
        addresses = ["2N7yv4p8G8yEaPddJxY41kPihnWvs39qCMf", "2MsHxyb2JS3pAySeNUsJ7mNnurtpeenDzLA"] # hdkeypath=m/0'/0'/0' and 1'
        addresses += ["bcrt1qrd3n235cj2czsfmsuvqqpr3lu6lg0ju7scl8gn", "bcrt1qfqeppuvj0ww98r6qghmdkj70tv8qpchehegrg8"] # wpkh subscripts corresponding to the above addresses
        desc = "sh(wpkh(" + xpub + "/0/0/*" + "))"

        self.log.info("Ranged descriptors cannot have labels")
        self.test_importdesc({"desc":descsum_create(desc),
                              "timestamp": "now",
                              "range": [0, 100],
                              "label": "test"},
                              success=False,
                              error_code=-8,
                              error_message='Ranged descriptors should not have a label')

        self.log.info("Private keys required for private keys enabled wallet")
        self.test_importdesc({"desc":descsum_create(desc),
                              "timestamp": "now",
                              "range": [0, 100]},
                              success=False,
                              error_code=-4,
                              error_message='Cannot import descriptor without private keys to a wallet with private keys enabled',
                              wallet=wpriv)

        self.log.info("Ranged descriptor import should warn without a specified range")
        self.test_importdesc({"desc": descsum_create(desc),
                               "timestamp": "now"},
                              success=True,
                              warnings=['Range not given, using default keypool range'])
        assert_equal(w1.getwalletinfo()['keypoolsize'], 0)

        # # Test importing of a ranged descriptor with xpriv
        self.log.info("Should not import a ranged descriptor that includes xpriv into a watch-only wallet")
        desc = "sh(wpkh(" + xpriv + "/0'/0'/*'" + "))"
        self.test_importdesc({"desc": descsum_create(desc),
                              "timestamp": "now",
                              "range": 1},
                             success=False,
                             error_code=-4,
                             error_message='Cannot import private keys to a wallet with private keys disabled')

        self.log.info("Should not import a descriptor with hardened derivations when private keys are disabled")
        self.test_importdesc({"desc": descsum_create("wpkh(" + xpub + "/1h/*)"),
                              "timestamp": "now",
                              "range": 1},
                             success=False,
                             error_code=-4,
                             error_message='Cannot expand descriptor. Probably because of hardened derivations without private keys provided')

        for address in addresses:
            test_address(w1,
                         address,
                         ismine=False,
                         solvable=False)

        self.test_importdesc({"desc": descsum_create(desc), "timestamp": "now", "range": -1},
                              success=False, error_code=-8, error_message='End of range is too high')

        self.test_importdesc({"desc": descsum_create(desc), "timestamp": "now", "range": [-1, 10]},
                              success=False, error_code=-8, error_message='Range should be greater or equal than 0')

        self.test_importdesc({"desc": descsum_create(desc), "timestamp": "now", "range": [(2 << 31 + 1) - 1000000, (2 << 31 + 1)]},
                              success=False, error_code=-8, error_message='End of range is too high')

        self.test_importdesc({"desc": descsum_create(desc), "timestamp": "now", "range": [2, 1]},
                              success=False, error_code=-8, error_message='Range specified as [begin,end] must not have begin after end')

        self.test_importdesc({"desc": descsum_create(desc), "timestamp": "now", "range": [0, 1000001]},
                              success=False, error_code=-8, error_message='Range is too large')

        self.log.info("Verify we can only extend descriptor's range")
        range_request = {"desc": descsum_create(desc), "timestamp": "now", "range": [5, 10], 'active': True}
        self.test_importdesc(range_request, wallet=wpriv, success=True)
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 6)
        self.test_importdesc({**range_request, "range": [0, 10]}, wallet=wpriv, success=True)
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 11)
        self.test_importdesc({**range_request, "range": [0, 20]}, wallet=wpriv, success=True)
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 21)
        # Can keep range the same
        self.test_importdesc({**range_request, "range": [0, 20]}, wallet=wpriv, success=True)
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 21)

        self.test_importdesc({**range_request, "range": [5, 10]}, wallet=wpriv, success=False,
                             error_code=-8, error_message='new range must include current range = [0,20]')
        self.test_importdesc({**range_request, "range": [0, 10]}, wallet=wpriv, success=False,
                             error_code=-8, error_message='new range must include current range = [0,20]')
        self.test_importdesc({**range_request, "range": [5, 20]}, wallet=wpriv, success=False,
                             error_code=-8, error_message='new range must include current range = [0,20]')
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 21)

        self.log.info("Check we can change descriptor internal flag")
        self.test_importdesc({**range_request, "range": [0, 20], "internal": True}, wallet=wpriv, success=True)
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 0)
        assert_raises_rpc_error(-4, 'This wallet has no available keys', wpriv.getnewaddress, '', 'p2sh-segwit')
        assert_equal(wpriv.getwalletinfo()['keypoolsize_hd_internal'], 21)
        wpriv.getrawchangeaddress('p2sh-segwit')

        self.test_importdesc({**range_request, "range": [0, 20], "internal": False}, wallet=wpriv, success=True)
        assert_equal(wpriv.getwalletinfo()['keypoolsize'], 21)
        wpriv.getnewaddress('', 'p2sh-segwit')
        assert_equal(wpriv.getwalletinfo()['keypoolsize_hd_internal'], 0)
        assert_raises_rpc_error(-4, 'This wallet has no available keys', wpriv.getrawchangeaddress, 'p2sh-segwit')

        # Make sure ranged imports import keys in order
        w1 = self.nodes[1].get_wallet_rpc('w1')
        self.log.info('Key ranges should be imported in order')
        xpub = "tpubDAXcJ7s7ZwicqjprRaEWdPoHKrCS215qxGYxpusRLLmJuT69ZSicuGdSfyvyKpvUNYBW1s2U3NSrT6vrCYB9e6nZUEvrqnwXPF8ArTCRXMY"
        addresses = [
            'bcrt1qtmp74ayg7p24uslctssvjm06q5phz4yrxucgnv', # m/0'/0'/0
            'bcrt1q8vprchan07gzagd5e6v9wd7azyucksq2xc76k8', # m/0'/0'/1
            'bcrt1qtuqdtha7zmqgcrr26n2rqxztv5y8rafjp9lulu', # m/0'/0'/2
            'bcrt1qau64272ymawq26t90md6an0ps99qkrse58m640', # m/0'/0'/3
            'bcrt1qsg97266hrh6cpmutqen8s4s962aryy77jp0fg0', # m/0'/0'/4
        ]

        self.test_importdesc({'desc': descsum_create('wpkh([80002067/0h/0h]' + xpub + '/*)'),
                              'active': True,
                              'range' : [0, 2],
                              'timestamp': 'now'
                             },
                             success=True)
        self.test_importdesc({'desc': descsum_create('sh(wpkh([abcdef12/0h/0h]' + xpub + '/*))'),
                              'active': True,
                              'range' : [0, 2],
                              'timestamp': 'now'
                             },
                             success=True)
        self.test_importdesc({'desc': descsum_create('pkh([12345678/0h/0h]' + xpub + '/*)'),
                              'active': True,
                              'range' : [0, 2],
                              'timestamp': 'now'
                             },
                             success=True)

        assert_equal(w1.getwalletinfo()['keypoolsize'], 5 * 3)
        for i, expected_addr in enumerate(addresses):
            received_addr = w1.getnewaddress('', 'bech32')
            assert_raises_rpc_error(-4, 'This wallet has no available keys', w1.getrawchangeaddress, 'bech32')
            assert_equal(received_addr, expected_addr)
            bech32_addr_info = w1.getaddressinfo(received_addr)
            assert_equal(bech32_addr_info['desc'][:23], 'wpkh([80002067/0h/0h/{}]'.format(i))

            shwpkh_addr = w1.getnewaddress('', 'p2sh-segwit')
            shwpkh_addr_info = w1.getaddressinfo(shwpkh_addr)
            assert_equal(shwpkh_addr_info['desc'][:26], 'sh(wpkh([abcdef12/0h/0h/{}]'.format(i))

            pkh_addr = w1.getnewaddress('', 'legacy')
            pkh_addr_info = w1.getaddressinfo(pkh_addr)
            assert_equal(pkh_addr_info['desc'][:22], 'pkh([12345678/0h/0h/{}]'.format(i))

            assert_equal(w1.getwalletinfo()['keypoolsize'], 4 * 3) # After retrieving a key, we don't refill the keypool again, so it's one less for each address type
        w1.keypoolrefill()
        assert_equal(w1.getwalletinfo()['keypoolsize'], 5 * 3)

        self.log.info("Check we can change next_index")
        # go back and forth with next_index
        for i in [4, 0, 2, 1, 3]:
            self.test_importdesc({'desc': descsum_create('wpkh([80002067/0h/0h]' + xpub + '/*)'),
                                  'active': True,
                                  'range': [0, 9],
                                  'next_index': i,
                                  'timestamp': 'now'
                                  },
                                 success=True)
            assert_equal(w1.getnewaddress('', 'bech32'), addresses[i])

        # Check active=False default
        self.log.info('Check imported descriptors are not active by default')
        self.test_importdesc({'desc': descsum_create('pkh([12345678/1h]' + xpub + '/*)'),
                              'range' : [0, 2],
                              'timestamp': 'now',
                              'internal': True
                             },
                             success=True)
        assert_raises_rpc_error(-4, 'This wallet has no available keys', w1.getrawchangeaddress, 'legacy')

        self.log.info('Check can activate inactive descriptor')
        self.test_importdesc({'desc': descsum_create('pkh([12345678]' + xpub + '/*)'),
                              'range': [0, 5],
                              'active': True,
                              'timestamp': 'now',
                              'internal': True
                              },
                             success=True)
        address = w1.getrawchangeaddress('legacy')
        assert_equal(address, "mpA2Wh9dvZT7yfELq1UnrUmAoc5qCkMetg")

        self.log.info('Check can deactivate active descriptor')
        self.test_importdesc({'desc': descsum_create('pkh([12345678]' + xpub + '/*)'),
                              'range': [0, 5],
                              'active': False,
                              'timestamp': 'now',
                              'internal': True
                              },
                             success=True)
        assert_raises_rpc_error(-4, 'This wallet has no available keys', w1.getrawchangeaddress, 'legacy')

        self.log.info('Verify activation state is persistent')
        w1.unloadwallet()
        self.nodes[1].loadwallet('w1')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', w1.getrawchangeaddress, 'legacy')

        # # Test importing a descriptor containing a WIF private key
        wif_priv = "cTe1f5rdT8A8DFgVWTjyPwACsDPJM9ff4QngFxUixCSvvbg1x6sh"
        address = "2MuhcG52uHPknxDgmGPsV18jSHFBnnRgjPg"
        desc = "sh(wpkh(" + wif_priv + "))"
        self.log.info("Should import a descriptor with a WIF private key as spendable")
        self.test_importdesc({"desc": descsum_create(desc),
                               "timestamp": "now"},
                              success=True,
                              wallet=wpriv)

        self.log.info('Test can import same descriptor with private key twice')
        self.test_importdesc({"desc": descsum_create(desc), "timestamp": "now"}, success=True, wallet=wpriv)

        test_address(wpriv,
                     address,
                     solvable=True,
                     ismine=True)
        txid = w0.sendtoaddress(address, 49.99995540)
        self.generatetoaddress(self.nodes[0], 6, w0.getnewaddress())
        tx = wpriv.createrawtransaction([{"txid": txid, "vout": 0}], {w0.getnewaddress(): 49.999})
        signed_tx = wpriv.signrawtransactionwithwallet(tx)
        w1.sendrawtransaction(signed_tx['hex'])

        # Make sure that we can use import and use multisig as addresses
        self.log.info('Test that multisigs can be imported, signed for, and getnewaddress\'d')
        self.nodes[1].createwallet(wallet_name="wmulti_priv", disable_private_keys=False, blank=True, descriptors=True)
        wmulti_priv = self.nodes[1].get_wallet_rpc("wmulti_priv")
        assert_equal(wmulti_priv.getwalletinfo()['keypoolsize'], 0)

        xprv1 = 'tprv8ZgxMBicQKsPevADjDCWsa6DfhkVXicu8NQUzfibwX2MexVwW4tCec5mXdCW8kJwkzBRRmAay1KZya4WsehVvjTGVW6JLqiqd8DdZ4xSg52'
        acc_xpub1 = 'tpubDCJtdt5dgJpdhW4MtaVYDhG4T4tF6jcLR1PxL43q9pq1mxvXgMS9Mzw1HnXG15vxUGQJMMSqCQHMTy3F1eW5VkgVroWzchsPD5BUojrcWs8'  # /84'/0'/0'
        chg_xpub1 = 'tpubDCXqdwWZcszwqYJSnZp8eARkxGJfHAk23KDxbztV4BbschfaTfYLTcSkSJ3TN64dRqwa1rnFUScsYormKkGqNbbPwkorQimVevXjxzUV9Gf'  # /84'/1'/0'
        xprv2 = 'tprv8ZgxMBicQKsPdSNWUhDiwTScDr6JfkZuLshTRwzvZGnMSnGikV6jxpmdDkC3YRc4T3GD6Nvg9uv6hQg73RVv1EiTXDZwxVbsLugVHU8B1aq'
        acc_xprv2 = 'tprv8gVCsmRAxVSxyUpsL13Y7ZEWBFPWbgS5E2MmFVNGuANrknvmmn2vWnmHvU8AwEFYzR2ji6EeZLSCLVacsYkvor3Pcb5JY5FGcevqTwYvdYx'
        acc_xpub2 = 'tpubDDBF2BTR6s8drwrfDei8WxtckGuSm1cyoKxYY1QaKSBFbHBYQArWhHPA6eJrzZej6nfHGLSURYSLHr7GuYch8aY5n61tGqgn8b4cXrMuoPH'
        chg_xpub2 = 'tpubDCYfZY2ceyHzYzMMVPt9MNeiqtQ2T7Uyp9QSFwYXh8Vi9iJFYXcuphJaGXfF3jUQJi5Y3GMNXvM11gaL4txzZgNGK22BFAwMXynnzv4z2Jh'
        xprv3 = 'tprv8ZgxMBicQKsPeonDt8Ka2mrQmHa61hQ5FQCsvWBTpSNzBFgM58cV2EuXNAHF14VawVpznnme3SuTbA62sGriwWyKifJmXntfNeK7zeqMCj1'
        acc_xpub3 = 'tpubDCsWoW1kuQB9kG5MXewHqkbjPtqPueRnXju7uM2NK7y3JYb2ajAZ9EiuZXNNuE4661RAfriBWhL8UsnAPpk8zrKKnZw1Ug7X4oHgMdZiU4E'
        chg_xpub3 = 'tpubDC6UGqnsQStngYuGD4MKsMy7eD1Yg9NTJfPdvjdG2JE5oZ7EsSL3WHg4Gsw2pR5K39ZwJ46M1wZayhedVdQtMGaUhq5S23PH6fnENK3V1sb'

        self.test_importdesc({"desc":"wsh(multi(2," + xprv1 + "/84h/0h/0h/*," + xprv2 + "/84h/0h/0h/*," + xprv3 + "/84h/0h/0h/*))#m2sr93jn",
                            "active": True,
                            "range": 1000,
                            "next_index": 0,
                            "timestamp": "now"},
                            success=True,
                            wallet=wmulti_priv)
        self.test_importdesc({"desc":"wsh(multi(2," + xprv1 + "/84h/1h/0h/*," + xprv2 + "/84h/1h/0h/*," + xprv3 + "/84h/1h/0h/*))#q3sztvx5",
                            "active": True,
                            "internal" : True,
                            "range": 1000,
                            "next_index": 0,
                            "timestamp": "now"},
                            success=True,
                            wallet=wmulti_priv)

        assert_equal(wmulti_priv.getwalletinfo()['keypoolsize'], 1001) # Range end (1000) is inclusive, so 1001 addresses generated
        addr = wmulti_priv.getnewaddress('', 'bech32') # uses receive 0
        assert_equal(addr, 'bcrt1qdt0qy5p7dzhxzmegnn4ulzhard33s2809arjqgjndx87rv5vd0fq2czhy8') # Derived at m/84'/0'/0'/0
        change_addr = wmulti_priv.getrawchangeaddress('bech32') # uses change 0
        assert_equal(change_addr, 'bcrt1qt9uhe3a9hnq7vajl7a094z4s3crm9ttf8zw3f5v9gr2nyd7e3lnsy44n8e') # Derived at m/84'/1'/0'/0
        assert_equal(wmulti_priv.getwalletinfo()['keypoolsize'], 1000)
        txid = w0.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 6)
        send_txid = wmulti_priv.sendtoaddress(w0.getnewaddress(), 8) # uses change 1
        decoded = wmulti_priv.gettransaction(txid=send_txid, verbose=True)['decoded']
        assert_equal(len(decoded['vin'][0]['txinwitness']), 4)
        self.sync_all()

        self.nodes[1].createwallet(wallet_name="wmulti_pub", disable_private_keys=True, blank=True, descriptors=True)
        wmulti_pub = self.nodes[1].get_wallet_rpc("wmulti_pub")
        assert_equal(wmulti_pub.getwalletinfo()['keypoolsize'], 0)

        self.test_importdesc({"desc":"wsh(multi(2,[7b2d0242/84h/0h/0h]" + acc_xpub1 + "/*,[59b09cd6/84h/0h/0h]" + acc_xpub2 + "/*,[e81a0532/84h/0h/0h]" + acc_xpub3 +"/*))#tsry0s5e",
                            "active": True,
                            "range": 1000,
                            "next_index": 0,
                            "timestamp": "now"},
                            success=True,
                            wallet=wmulti_pub)
        self.test_importdesc({"desc":"wsh(multi(2,[7b2d0242/84h/1h/0h]" + chg_xpub1 + "/*,[59b09cd6/84h/1h/0h]" + chg_xpub2 + "/*,[e81a0532/84h/1h/0h]" + chg_xpub3 + "/*))#c08a2rzv",
                            "active": True,
                            "internal" : True,
                            "range": 1000,
                            "next_index": 0,
                            "timestamp": "now"},
                            success=True,
                            wallet=wmulti_pub)

        assert_equal(wmulti_pub.getwalletinfo()['keypoolsize'], 1000) # The first one was already consumed by previous import and is detected as used
        addr = wmulti_pub.getnewaddress('', 'bech32') # uses receive 1
        assert_equal(addr, 'bcrt1qp8s25ckjl7gr6x2q3dx3tn2pytwp05upkjztk6ey857tt50r5aeqn6mvr9') # Derived at m/84'/0'/0'/1
        change_addr = wmulti_pub.getrawchangeaddress('bech32') # uses change 2
        assert_equal(change_addr, 'bcrt1qp6j3jw8yetefte7kw6v5pc89rkgakzy98p6gf7ayslaveaxqyjusnw580c') # Derived at m/84'/1'/0'/2
        assert send_txid in self.nodes[0].getrawmempool(True)
        assert send_txid in (x['txid'] for x in wmulti_pub.listunspent(0))
        assert_equal(wmulti_pub.getwalletinfo()['keypoolsize'], 999)

        # generate some utxos for next tests
        utxo = self.create_outpoints(w0, outputs=[{addr: 10}])[0]

        addr2 = wmulti_pub.getnewaddress('', 'bech32')
        utxo2 = self.create_outpoints(w0, outputs=[{addr2: 10}])[0]

        self.generate(self.nodes[0], 6)
        assert_equal(wmulti_pub.getbalance(), wmulti_priv.getbalance())

        # Make sure that descriptor wallets containing multiple xpubs in a single descriptor load correctly
        wmulti_pub.unloadwallet()
        self.nodes[1].loadwallet('wmulti_pub')

        self.log.info("Multisig with distributed keys")
        self.nodes[1].createwallet(wallet_name="wmulti_priv1", descriptors=True)
        wmulti_priv1 = self.nodes[1].get_wallet_rpc("wmulti_priv1")
        res = wmulti_priv1.importdescriptors([
        {
            "desc": descsum_create("wsh(multi(2," + xprv1 + "/84h/0h/0h/*,[59b09cd6/84h/0h/0h]" + acc_xpub2 + "/*,[e81a0532/84h/0h/0h]" + acc_xpub3 + "/*))"),
            "active": True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        },
        {
            "desc": descsum_create("wsh(multi(2," + xprv1 + "/84h/1h/0h/*,[59b09cd6/84h/1h/0h]" + chg_xpub2 + "/*,[e81a0532/84h/1h/0h]" + chg_xpub3 + "/*))"),
            "active": True,
            "internal" : True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        }])
        assert_equal(res[0]['success'], True)
        assert_equal(res[0]['warnings'][0], 'Not all private keys provided. Some wallet functionality may return unexpected errors')
        assert_equal(res[1]['success'], True)
        assert_equal(res[1]['warnings'][0], 'Not all private keys provided. Some wallet functionality may return unexpected errors')

        self.nodes[1].createwallet(wallet_name='wmulti_priv2', blank=True, descriptors=True)
        wmulti_priv2 = self.nodes[1].get_wallet_rpc('wmulti_priv2')
        res = wmulti_priv2.importdescriptors([
        {
            "desc": descsum_create("wsh(multi(2,[7b2d0242/84h/0h/0h]" + acc_xpub1 + "/*," + xprv2 + "/84h/0h/0h/*,[e81a0532/84h/0h/0h]" + acc_xpub3 + "/*))"),
            "active": True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        },
        {
            "desc": descsum_create("wsh(multi(2,[7b2d0242/84h/1h/0h]" + chg_xpub1 + "/*," + xprv2 + "/84h/1h/0h/*,[e81a0532/84h/1h/0h]" + chg_xpub3 + "/*))"),
            "active": True,
            "internal" : True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        }])
        assert_equal(res[0]['success'], True)
        assert_equal(res[0]['warnings'][0], 'Not all private keys provided. Some wallet functionality may return unexpected errors')
        assert_equal(res[1]['success'], True)
        assert_equal(res[1]['warnings'][0], 'Not all private keys provided. Some wallet functionality may return unexpected errors')

        rawtx = self.nodes[1].createrawtransaction([utxo], {w0.getnewaddress(): 9.999})
        tx_signed_1 = wmulti_priv1.signrawtransactionwithwallet(rawtx)
        assert_equal(tx_signed_1['complete'], False)
        tx_signed_2 = wmulti_priv2.signrawtransactionwithwallet(tx_signed_1['hex'])
        assert_equal(tx_signed_2['complete'], True)
        self.nodes[1].sendrawtransaction(tx_signed_2['hex'])

        self.log.info("We can create and use a huge multisig under P2WSH")
        self.nodes[1].createwallet(wallet_name='wmulti_priv_big', blank=True, descriptors=True)
        wmulti_priv_big = self.nodes[1].get_wallet_rpc('wmulti_priv_big')
        xkey = "tprv8ZgxMBicQKsPeZSeYx7VXDDTs3XrTcmZQpRLbAeSQFCQGgKwR4gKpcxHaKdoTNHniv4EPDJNdzA3KxRrrBHcAgth8fU5X4oCndkkxk39iAt/*"
        xkey_int = "tprv8ZgxMBicQKsPeZSeYx7VXDDTs3XrTcmZQpRLbAeSQFCQGgKwR4gKpcxHaKdoTNHniv4EPDJNdzA3KxRrrBHcAgth8fU5X4oCndkkxk39iAt/1/*"
        res = wmulti_priv_big.importdescriptors([
        {
            "desc": descsum_create(f"wsh(sortedmulti(20,{(xkey + ',') * 19}{xkey}))"),
            "active": True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        },
        {
            "desc": descsum_create(f"wsh(sortedmulti(20,{(xkey_int + ',') * 19}{xkey_int}))"),
            "active": True,
            "internal": True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        }])
        assert_equal(res[0]['success'], True)
        assert_equal(res[1]['success'], True)

        addr = wmulti_priv_big.getnewaddress()
        w0.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)
        # It is standard and would relay.
        txid = wmulti_priv_big.sendtoaddress(w0.getnewaddress(), 9.999)
        decoded = wmulti_priv_big.gettransaction(txid=txid, verbose=True)['decoded']
        # 20 sigs + dummy + witness script
        assert_equal(len(decoded['vin'][0]['txinwitness']), 22)


        self.log.info("Under P2SH, multisig are standard with up to 15 "
                      "compressed keys")
        self.nodes[1].createwallet(wallet_name='multi_priv_big_legacy',
                                   blank=True, descriptors=True)
        multi_priv_big = self.nodes[1].get_wallet_rpc('multi_priv_big_legacy')
        res = multi_priv_big.importdescriptors([
        {
            "desc": descsum_create(f"sh(multi(15,{(xkey + ',') * 14}{xkey}))"),
            "active": True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        },
        {
            "desc": descsum_create(f"sh(multi(15,{(xkey_int + ',') * 14}{xkey_int}))"),
            "active": True,
            "internal": True,
            "range": 1000,
            "next_index": 0,
            "timestamp": "now"
        }])
        assert_equal(res[0]['success'], True)
        assert_equal(res[1]['success'], True)

        addr = multi_priv_big.getnewaddress("", "legacy")
        w0.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 6)
        # It is standard and would relay.
        txid = multi_priv_big.sendtoaddress(w0.getnewaddress(), 10, "", "", True)
        decoded = multi_priv_big.gettransaction(txid=txid, verbose=True)['decoded']

        self.log.info("Amending multisig with new private keys")
        self.nodes[1].createwallet(wallet_name="wmulti_priv3", descriptors=True)
        wmulti_priv3 = self.nodes[1].get_wallet_rpc("wmulti_priv3")
        res = wmulti_priv3.importdescriptors([
            {
                "desc": descsum_create("wsh(multi(2," + xprv1 + "/84h/0h/0h/*,[59b09cd6/84h/0h/0h]" + acc_xpub2 + "/*,[e81a0532/84h/0h/0h]" + acc_xpub3 + "/*))"),
                "active": True,
                "range": 1000,
                "next_index": 0,
                "timestamp": "now"
            }])
        assert_equal(res[0]['success'], True)
        res = wmulti_priv3.importdescriptors([
            {
                "desc": descsum_create("wsh(multi(2," + xprv1 + "/84h/0h/0h/*,[59b09cd6/84h/0h/0h]" + acc_xprv2 + "/*,[e81a0532/84h/0h/0h]" + acc_xpub3 + "/*))"),
                "active": True,
                "range": 1000,
                "next_index": 0,
                "timestamp": "now"
            }])
        assert_equal(res[0]['success'], True)

        rawtx = self.nodes[1].createrawtransaction([utxo2], {w0.getnewaddress(): 9.999})
        tx = wmulti_priv3.signrawtransactionwithwallet(rawtx)
        assert_equal(tx['complete'], True)
        self.nodes[1].sendrawtransaction(tx['hex'])

        self.log.info("Combo descriptors cannot be active")
        self.test_importdesc({"desc": descsum_create("combo(tpubDCJtdt5dgJpdhW4MtaVYDhG4T4tF6jcLR1PxL43q9pq1mxvXgMS9Mzw1HnXG15vxUGQJMMSqCQHMTy3F1eW5VkgVroWzchsPD5BUojrcWs8/*)"),
                              "active": True,
                              "range": 1,
                              "timestamp": "now"},
                              success=False,
                              error_code=-4,
                              error_message="Combo descriptors cannot be set to active")

        self.log.info("Descriptors with no type cannot be active")
        self.test_importdesc({"desc": descsum_create("pk(tpubDCJtdt5dgJpdhW4MtaVYDhG4T4tF6jcLR1PxL43q9pq1mxvXgMS9Mzw1HnXG15vxUGQJMMSqCQHMTy3F1eW5VkgVroWzchsPD5BUojrcWs8/*)"),
                              "active": True,
                              "range": 1,
                              "timestamp": "now"},
                              success=True,
                              warnings=["Unknown output type, cannot set descriptor to active."])

        self.log.info("Test importing a descriptor to an encrypted wallet")

        descriptor = {"desc": descsum_create("pkh(" + xpriv + "/1h/*h)"),
                              "timestamp": "now",
                              "active": True,
                              "range": [0,4000],
                              "next_index": 4000}

        self.nodes[0].createwallet("temp_wallet", blank=True, descriptors=True)
        temp_wallet = self.nodes[0].get_wallet_rpc("temp_wallet")
        temp_wallet.importdescriptors([descriptor])
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 1, temp_wallet.getnewaddress())
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 1, temp_wallet.getnewaddress())

        self.nodes[0].createwallet("encrypted_wallet", blank=True, descriptors=True, passphrase="passphrase")
        encrypted_wallet = self.nodes[0].get_wallet_rpc("encrypted_wallet")

        descriptor["timestamp"] = 0
        descriptor["next_index"] = 0

        encrypted_wallet.walletpassphrase("passphrase", 99999)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as thread:
            with self.nodes[0].assert_debug_log(expected_msgs=["Rescan started from block 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206... (slow variant inspecting all blocks)"], timeout=10):
                importing = thread.submit(encrypted_wallet.importdescriptors, requests=[descriptor])

            # Set the passphrase timeout to 1 to test that the wallet remains unlocked during the rescan
            self.nodes[0].cli("-rpcwallet=encrypted_wallet").walletpassphrase("passphrase", 1)

            try:
                self.nodes[0].cli("-rpcwallet=encrypted_wallet").walletlock()
            except JSONRPCException as e:
                assert e.error["code"] == -4 and "Error: the wallet is currently being used to rescan the blockchain for related transactions. Please call `abortrescan` before locking the wallet." in e.error["message"]

            try:
                self.nodes[0].cli("-rpcwallet=encrypted_wallet").walletpassphrasechange("passphrase", "newpassphrase")
            except JSONRPCException as e:
                assert e.error["code"] == -4 and "Error: the wallet is currently being used to rescan the blockchain for related transactions. Please call `abortrescan` before changing the passphrase." in e.error["message"]

            assert_equal(importing.result(), [{"success": True}])

        assert_equal(temp_wallet.getbalance(), encrypted_wallet.getbalance())

        self.log.info("Multipath descriptors")
        self.nodes[1].createwallet(wallet_name="multipath", descriptors=True, blank=True)
        w_multipath = self.nodes[1].get_wallet_rpc("multipath")
        self.nodes[1].createwallet(wallet_name="multipath_split", descriptors=True, blank=True)
        w_multisplit = self.nodes[1].get_wallet_rpc("multipath_split")
        timestamp = int(time.time())

        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10;20>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now",
                              "label": "some label"},
                              success=False,
                              error_code=-8,
                              error_message="Multipath descriptors should not have a label",
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10;20>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": timestamp,
                              "internal": True},
                              success=False,
                              error_code=-5,
                              error_message="Cannot have multipath descriptor while also specifying \'internal\'",
                              wallet=w_multipath)

        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10;20>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": timestamp},
                              success=True,
                              wallet=w_multipath)

        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/10/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": timestamp},
                              success=True,
                              wallet=w_multisplit)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/20/0/*)"),
                              "active": True,
                              "range": 10,
                              "internal": True,
                              "timestamp": timestamp},
                              success=True,
                              wallet=w_multisplit)
        for _ in range(0, 10):
            assert_equal(w_multipath.getnewaddress(address_type="bech32"), w_multisplit.getnewaddress(address_type="bech32"))
            assert_equal(w_multipath.getrawchangeaddress(address_type="bech32"), w_multisplit.getrawchangeaddress(address_type="bech32"))
        assert_equal(sorted(w_multipath.listdescriptors()["descriptors"], key=lambda x: x["desc"]), sorted(w_multisplit.listdescriptors()["descriptors"], key=lambda x: x["desc"]))

        self.nodes[1].createwallet(wallet_name="multipath2", descriptors=True, blank=True)
        w_multipath = self.nodes[1].get_wallet_rpc("multipath2")
        self.test_importdesc({"desc": descsum_create(f"wsh(and_v(v:pk({xpub}/<0;1>/*),pk({xpriv}/<0';1'>/*)))"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              warnings=["Not all private keys provided. Some wallet functionality may return unexpected errors",
                                        "Not all private keys provided. Some wallet functionality may return unexpected errors"],
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wsh(and_v(v:pk({xpriv}/<0;1>/*),or_d(pk({xpriv}/<1;2>/*),older(1000))))"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10';20'>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10';20h>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10h;20'>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10h;20';30>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<10>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=False,
                              error_code=-5,
                              error_message="wpkh(): Multipath key path specifiers must have at least two items",
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<2147483647;2147483647'>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<0;1;2;3;4>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<2147483648;2147483647'>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              error_code=-5,
                              error_message="wpkh(): Key path value 2147483648 is out of range",
                              success=False,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<2147483647;2147483648'>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              error_code=-5,
                              error_message="wpkh(): Key path value 2147483648 is out of range",
                              success=False,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<0;1>/<0;1>/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              error_code=-5,
                              error_message="wpkh(): Multiple multipath key path specifiers found",
                              success=False,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<0;1>/1/*)"),
                              "internal": True,
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              error_code=-5,
                              error_message="Cannot have multipath descriptor while also specifying 'internal'",
                              success=False,
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create("wsh(pk([d9a64db6/48'/1'/<0';1'>/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/1/*))"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              error_code=-5,
                              error_message="pk(): Key path value '<0';1'>' specifies multipath in a section where multipath is not allowed",
                              success=False,
                              wallet=w_multipath)

        self.nodes[1].createwallet(wallet_name="multipath3", descriptors=True, blank=True)
        w_multipath = self.nodes[1].get_wallet_rpc("multipath3")
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpub}/<0;1'>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=False,
                              error_code=-4,
                              error_message="Cannot import descriptor without private keys to a wallet with private keys enabled",
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpub}/<0h;1>/0/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=False,
                              error_code=-4,
                              error_message="Cannot expand descriptor. Probably because of hardened derivations without private keys provided",
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<1;1>/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=False,
                              error_code=-5,
                              error_message="wpkh(): Duplicated key path value 1 in multipath specifier",
                              wallet=w_multipath)
        self.test_importdesc({"desc": descsum_create(f"wpkh({xpriv}/<1;1;1>/*)"),
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=False,
                              error_code=-5,
                              error_message="wpkh(): Duplicated key path value 1 in multipath specifier",
                              wallet=w_multipath)

        self.nodes[1].createwallet(wallet_name="liana", disable_private_keys=True, descriptors=True, blank=True)
        w_multipath = self.nodes[1].get_wallet_rpc("liana")
        self.test_importdesc({"desc": "wsh(or_d(pk([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*),and_v(v:pkh([33fa0ffc/48'/1'/0'/2']tpubDEqzYAym2MnGqKdqu2ZtGQkDTSrvDWCrcoamspjRJR78nr8w5tAgu371r8LtcyWWWXGemenTMxmoLhQM3ww8gUfobBXUWxLEkfR7kGjD6jC/<0;1>/*),older(65535))))#r5c5gqy8",
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": "tr([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*,and_v(v:pk([33fa0ffc/48'/1'/0'/2']tpubDEqzYAym2MnGqKdqu2ZtGQkDTSrvDWCrcoamspjRJR78nr8w5tAgu371r8LtcyWWWXGemenTMxmoLhQM3ww8gUfobBXUWxLEkfR7kGjD6jC/<0;1>/*),older(65535)))#9j8845ej",
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": "wsh(or_d(multi(2,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<0;1>/*,[d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*),and_v(v:thresh(1,pkh([d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<2;3>/*),a:pkh([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<2;3>/*)),older(65535))))#y42k746f",
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": "tr(tpubD6NzVbkrYhZ4WX3dbgp6RDJZFMKAh1n44x3szXsf585MaWByERJfDBBpydeUH2RFg8nj5GPrk22vecCZzFYRMNfHc2SeQj6oSjipHmEymgV/<0;1>/*,{and_v(v:multi_a(1,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<2;3>/*,[d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<2;3>/*),older(65535)),multi_a(2,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<0;1>/*,[d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*)})#t0hmfjap",
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": "wsh(or_i(and_v(v:thresh(1,pkh([d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<6;7>/*),a:pkh([7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<6;7>/*)),older(65535)),or_i(and_v(v:thresh(2,pkh([d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<4;5>/*),a:pkh([7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<4;5>/*)),older(45000)),or_i(and_v(v:pkh([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<6;7>/*),older(40000)),or_i(and_v(v:thresh(2,pkh([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<4;5>/*),a:pkh([7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<2;3>/*)),older(35001)),or_d(multi(3,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<0;1>/*,[d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*,[7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<0;1>/*),and_v(v:thresh(2,pkh([d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<2;3>/*),a:pkh([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<2;3>/*)),older(30000))))))))#a34gqnj7",
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
        self.test_importdesc({"desc": "tr(tpubD6NzVbkrYhZ4XVMhAvtZjiXAYJgHjCysEZn9V2fEPfvanysCxV2CmATEyQW5po9WoD5VG4KBxNsgXUuh6eYnrKpyYdyQysM3Kso6mj2DFuD/<0;1>/*,{{{and_v(v:pk([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<6;7>/*),older(40000)),and_v(v:multi_a(2,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<4;5>/*,[7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<4;5>/*),older(45000))},{and_v(v:multi_a(1,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<6;7>/*,[7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<6;7>/*),older(65535)),{and_v(v:multi_a(2,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<2;3>/*,[d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<2;3>/*),older(30000)),and_v(v:multi_a(2,[d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<4;5>/*,[7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<2;3>/*),older(35001))}}},multi_a(3,[d9a64db6/48'/1'/0'/2']tpubDERzCQj7Gi1mehpkHMoJcCRx1ckWNzbMuiiujVEtCRYZXsojbQNLKJQM66oQEgwyDMHMtKM1GTSUeCM8uC4LtkzKR2Nco7iBTmNuKoZeL1d/<0;1>/*,[d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*,[7cab1066/48'/1'/0'/2']tpubDDvqWeedNeqAfoMYPAV5ewJcgQEuuAC9en8UzxZ3PSqiDZcjpLZSXs9yu2S4hYcQb6S7UrSy8eBvk199WgzAsjWmaE8TW87q3riaXfWcRQ6/<0;1>/*)})#cnlc926x",
                              "active": True,
                              "range": 10,
                              "timestamp": "now"},
                              success=True,
                              wallet=w_multipath)
if __name__ == '__main__':
    ImportDescriptorsTest().main()
