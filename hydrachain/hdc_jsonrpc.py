import os

from pyethapp.jsonrpc import Personal as eth_Personal
from pyethapp.jsonrpc import JSONRPCServer as eth_JSONRPCServer
from pyethapp.jsonrpc import decode_arg, encode_res, address_decoder
from pyethapp.jsonrpc import Web3, Net, Compilers, DB, Chain, Miner, FilterManager

from hydrachain.hdc_account import Account

class Personal(eth_Personal):

    @public
    @encode_res(address_encoder)
    def newUser(self, name, passwd):
        account = Account.new(username=name, password=passwd)
        account.path = os.path.join(self.app.services.accounts.keysore_dir, account.address.encode('hex'))
        self.app.services.accounts.add_account(account)
        account.lock()
        assert account.locked
        assert self.app.services.accounts.find(account.address.encode('hex'))
        return account.address

    @public
    @decode_arg('account_address', address_decoder)
    def unlockUser(self, name, passwd, duration):
        try:
            account = self.app.services.accounts.get_by_username(name)
            account.unlock(passwd)
            gevent.spawn_later(duration, lambda: account.lock())
            return not account.locked
        except KeyError:
            return False

    @public
    @decode_arg('account_address', address_decoder)
    def lockUser(self, name):
        try:
            account = self.app.services.accounts.get_by_username(name)
            account.lock()
            return account.locked
        except KeyError:
            return False

class JSONRPCServer(eth_JSONRPCServer):
    @classmethod
    def subdispatcher_classes(cls):
        return (Web3, Personal, Net, Compilers, DB, Chain, Miner, FilterManager)
