import nose

import pkilib.server.checks as checks

LOCALHOST_A = 'localhost'
LOCALHOST_PTR = '127.0.0.1'


class test_valid_fqdn:
    def test_integer_fqdn(self):
        assert checks.valid_fqdn(123456789) == False

    def test_undefined_fqdn(self):
        assert checks.valid_fqdn(None) == False

    def test_empty_fqdn(self):
        assert checks.valid_fqdn('') == False

    def test_fqdn_has_underscore(self):
        assert checks.valid_fqdn('some_host.domain') is False

    def test_tld_start_dash(self):
        assert checks.valid_fqdn('some.host.-tld') is False

    def test_tld_end_dash(self):
        assert checks.valid_fqdn('some.host.tld-') is False

    def test_tld_single_dash(self):
        assert checks.valid_fqdn('some.host.-') is False

    def test_fqdn_1component(self):
        assert checks.valid_fqdn('some') is True

    def test_fqdn_2component(self):
        assert checks.valid_fqdn('some.host') is True

    def test_fqdn_3component(self):
        assert checks.valid_fqdn('some.host.name') is True


class test_owns_fqdn:
    def test_undefined_srcip(self):
        assert checks.owns_fqdn(None, LOCALHOST_A) is False

    def test_empty_srcip(self):
        assert checks.owns_fqdn('', LOCALHOST_A) is False

    def test_numeric_srcip(self):
        assert checks.owns_fqdn(12345, LOCALHOST_A) is False

    def test_undefined_fqdn(self):
        assert checks.owns_fqdn(LOCALHOST_PTR, None) is False

    def test_empty_fqdn(self):
        assert checks.owns_fqdn(LOCALHOST_PTR, '') is False

    def test_numeric_fqdn(self):
        assert checks.owns_fqdn(LOCALHOST_PTR, 12345) is False

    def test_unowned_fqdn(self):
        assert checks.owns_fqdn(LOCALHOST_PTR, 'example.com') is False

    def test_invalid_fqdn(self):
        assert checks.owns_fqdn(LOCALHOST_PTR, 'some_host_name') is False

    def test_nonexisting_fqdn(self):
        assert checks.owns_fqdn(LOCALHOST_PTR, 'some.random.host') is False

    def test_unowned_fqdn_permissive(self):
        old_value = checks.PERMISSIVE_MODE
        checks.PERMISSIVE_MODE = True
        assert checks.owns_fqdn(LOCALHOST_PTR, 'example.com') is True
        checks.PERMISSIVE_MODE = old_value

    def test_owned_fqdn(self):
        assert checks.owns_fqdn(LOCALHOST_PTR, LOCALHOST_A) is True
