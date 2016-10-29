from ethereum import keys
from pyethapp.accounts import Account as eth_Account
from pyethapp.accounts import AccountsService as eth_AccountsService

class Account( eth_Account ):
    
    """Represents an account.

    :ivar keystore: the key store as a dictionary (as decoded from json)
    :ivar locked: `True` if the account is locked and neither private nor public keys can be
                  accessed, otherwise `False`
    :ivar path: absolute path to the associated keystore file (`None` for in-memory accounts)
    """

    def __init__(self, keystore, username, password=None, path=None):
        self.keystore = keystore
        self.username = username
        try:
            self._address = self.keystore['address'].decode('hex')
        except KeyError:
            self._address = None
        self.locked = True
        if password is not None:
            self.unlock(password)
        if path is not None:
            self.path = os.path.abspath(path)
        else:
            self.path = None

    @classmethod
    def new(cls, username, password, key=None, uuid=None, path=None):
        """Create a new account.

        Note that this creates the account in memory and does not store it on disk.

        :param password: the password used to encrypt the private key
        :param key: the private key, or `None` to generate a random one
        :param uuid: an optional id
        """
        if key is None:
            key = mk_random_privkey()
        keystore = keys.make_keystore_json(key, password)
        keystore['id'] = uuid
        return Account(keystore, username, password, path)

    @classmethod
    def load(cls, path, password=None):
        """Load an account from a keystore file.

        :param path: full path to the keyfile
        :param password: the password to decrypt the key file or `None` to leave it encrypted
        """
        with open(path) as f:
            keystore = json.load(f)
        if not keys.check_keystore_json(keystore):
            raise ValueError('Invalid keystore file')
        return Account(keystore, keystore['username'], password, path=path)

    def dump(self, include_address=True, include_id=True):
        """Dump the keystore for later disk storage.

        The result inherits the entries `'crypto'` and `'version`' from `account.keystore`, and
        adds `'address'` and `'id'` in accordance with the parameters `'include_address'` and
        `'include_id`'.

        If address or id are not known, they are not added, even if requested.

        :param include_address: flag denoting if the address should be included or not
        :param include_id: flag denoting if the id should be included or not
        """
        d = {}
        d['crypto'] = self.keystore['crypto']
        d['version'] = self.keystore['version']
        d['username'] = self.keystore['username']
        if include_address and self.address is not None:
            d['address'] = self.address.encode('hex')
        if include_id and self.uuid is not None:
            d['id'] = self.uuid
        return json.dumps(d)

    @property
    def username(self):
        try:
            return self.keystore['username']
        except KeyError:
            raise ValueError('Account No Username')
    
    @username.setter
    def username(self, value):
        if isinstance( value, basestring ):
            self.keystore['username'] = value
        else:
            raise valueError('Invalid Username Value')


class AccountsService(eth_AccountsService):

    """Service that manages accounts.

    At initialization, this service collects the accounts stored as key files in the keystore
    directory (config option `accounts.keystore_dir`) and below.

    To add more accounts, use :method:`add_account`.

    :ivar accounts: the :class:`Account`s managed by this service, sorted by the paths to their
                    keystore files
    :ivar keystore_dir: absolute path to the keystore directory
    """
    def __init__(self, app):
        super(AccountsService, self).__init__(app)
        
        self.accounts = []
        if not os.path.exists(self.keystore_dir):
            log.warning('keystore directory does not exist', directory=self.keystore_dir)
        elif not os.path.isdir(self.keystore_dir):
            log.error('configured keystore directory is a file, not a directory',
                      directory=self.keystore_dir)
        else:
            # traverse file tree rooted at keystore_dir
            log.info('searching for key files', directory=self.keystore_dir)
            for dirpath, _, filenames in os.walk(self.keystore_dir):
                for filename in [os.path.join(dirpath, filename) for filename in filenames]:
                    try:
                        self.accounts.append(Account.load(filename))
                    except ValueError:
                        log.warning('invalid file skipped in keystore directory',
                                    path=filename)
        self.accounts.sort(key=lambda account: account.path)  # sort accounts by path
        if not self.accounts:
            log.warn('no accounts found')
        else:
            log.info('found account(s)', accounts=self.accounts)

    def add_account(self, account, store=True, include_address=True, include_id=True):
        if len([acct for acct in self.accounts if acct.username == account.username]) > 0:
            log.error('could not add account (USERNAME collision)', username=account.username)
            raise ValueError('Could not add account (USERNAME collision)')
        super(AccountsService, self).add_account( account, store, include_address, include_id )

    def find(self, identifier):
        try:
            return self.get_by_username(username)
        except KeyError:
            return super(AccountsService, self).find( identifier )

    def get_by_username(self, username):
        accts = [acct for acct in self.accounts if acct.username == username]
        assert len(accts) <= 1
        if len(accts) == 0:
            raise KeyError('account with username {} unknown'.format(username))
        elif len(accts) > 1:
            log.warning('multiple accounts with same username found', username=username)
        return accts[0]

    def __getitem__(self, username_or_address_or_idx):
        if isinstance(username_or_address_or_idx, basestring):
            return get_by_username( username_or_address_or_idx )
        else:
            return super(AccountsService, self).__getitem__( username_or_address_or_idx )

