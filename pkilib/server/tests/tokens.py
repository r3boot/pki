import json
import os

import pkilib.utils as utils
import pkilib.server.tokens as tokens

STORE = './workspace/tokens.json'
TEST_HOST = 'some.host.name'


class test_validate_store:
    def setUp(self):
        if os.path.exists(STORE):
            os.unlink(STORE)
        self.store = tokens.TokenStore(STORE)

    def tearDown(self):
        if os.path.exists(STORE):
            os.unlink(STORE)

    def test_undefined(self):
        assert self.store.validate_store(None) is False

    def test_nondict(self):
        assert self.store.validate_store('abcde') is False

    def test_invalid_fields(self):
        assert self.store.validate_store({'a': 'b'}) is False

    def test_fqdn_field_invalid(self):
        data = {12345: utils.gentoken()}
        assert self.store.validate_store(data) is False

    def test_token_field_undefined(self):
        data = {TEST_HOST: None}
        assert self.store.validate_store(data) is False

    def test_token_field_integer(self):
        data = {TEST_HOST: 12345}
        assert self.store.validate_store(data) is False

    def test_token_field_invalid(self):
        data = {TEST_HOST: 'invalid'}
        assert self.store.validate_store(data) is False

    def test_valid_fields(self):
        data = {TEST_HOST: utils.gentoken()}
        assert self.store.validate_store(data) is True


class test_load_exceptions:
    def test_undefined_store(self):
        store = tokens.TokenStore(None)
        assert store.load() is False

    def test_integer_store(self):
        store = tokens.TokenStore(12345)
        assert store.load() is False

    def test_nonexisting_store(self):
        store = tokens.TokenStore('/nonexisting/token/store.json')
        assert store.load() is True


class test_load:
    def setUp(self):
        if os.path.exists(STORE):
            os.unlink(STORE)
        self.data = {TEST_HOST: utils.gentoken()}
        open(STORE, 'w').write(json.dumps(self.data))
        self.store = tokens.TokenStore(STORE)

    def tearDown(self):
        if os.path.exists(STORE):
            os.unlink(STORE)

    def test_invalid_store(self):
        open(STORE, 'w').write(json.dumps(STORE))
        assert self.store.load() is False

    def test_empty_store(self):
        open(STORE, 'w').write('')
        assert self.store.load() is False

    def test_valid_store(self):
        token = self.data[TEST_HOST]
        assert self.store.load() is True
        assert self.store._store[TEST_HOST] == token


class test_save_exceptions:
    def test_undefined_store(self):
        store = tokens.TokenStore(None)
        assert store.save() is False

    def test_integer_store(self):
        store = tokens.TokenStore(12345)
        assert store.save() is False

    def test_nonexisting_store(self):
        store = tokens.TokenStore('/some/random/nonexisting/token/store.json')
        assert store.save() is False


class test_save:
    def setUp(self):
        if os.path.exists(STORE):
            os.unlink(STORE)
        self.store = tokens.TokenStore(STORE)

    def tearDown(self):
        if os.path.exists(STORE):
            os.unlink(STORE)

    def test_create_store(self):
        assert self.store.save() is True


class test_new_exceptions:
    def setUp(self):
        self.store = tokens.TokenStore(STORE)

    def test_invalid_fqdn(self):
        assert self.store.new(12345) == False


class test_new:
    def setUp(self):
        if os.path.exists(STORE):
            os.unlink(STORE)
        self.store = tokens.TokenStore(STORE)
        self.token = self.store.new(TEST_HOST)
        assert self.token is not False

    def tearDown(self):
        if os.path.exists(STORE):
            os.unlink(STORE)

    def test_generate_duplicate(self):
        assert self.store.new(TEST_HOST) is False

    def test_generates_token(self):
        assert isinstance(self.token, str) is True
        assert len(self.token) == 64

    def test_updates_backingstore(self):
        raw_data = open(STORE, 'r').read()
        assert self.token in raw_data


class test_get:
    def setUp(self):
        if os.path.exists(STORE):
            os.unlink(STORE)
        self.store = tokens.TokenStore(STORE)
        self.token = self.store.new(TEST_HOST)
        assert self.token is not False

    def tearDown(self):
        if os.path.exists(STORE):
            os.unlink(STORE)

    def test_invalid_fqdn(self):
        assert self.store.get(12345) is False

    def test_nonexisting_fqdn(self):
        assert self.store.get('undefined.host.name') is False

    def test_existing_fqdn(self):
        assert self.store.get(TEST_HOST) == self.token


class test_validate:
    def setUp(self):
        if os.path.exists(STORE):
            os.unlink(STORE)
        self.store = tokens.TokenStore(STORE)
        self.token = self.store.new(TEST_HOST)
        assert self.token is not False

    def tearDown(self):
        if os.path.exists(STORE):
            os.unlink(STORE)

    def test_invalid_fqdn(self):
        assert self.store.validate(12345, self.token) is False

    def test_undefined_token(self):
        assert self.store.validate(TEST_HOST, None) is False

    def test_invalidate(self):
        assert self.store.validate(TEST_HOST, 12345) is False

    def test_non64char_token(self):
        assert self.store.validate(TEST_HOST, 'abcdef') is False

    def test_valid(self):
        assert self.store.validate(TEST_HOST, self.token) is True
