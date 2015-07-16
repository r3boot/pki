import nose

import pkilib.server.checks as checks


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
