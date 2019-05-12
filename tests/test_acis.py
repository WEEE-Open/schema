#!/usr/bin/env python3

import ldap
import ldif
from ldap.modlist import addModlist
import pytest


SUFFIX = 'dc=example,dc=local'


class MyLDIFWriter(ldif.LDIFParser):
    def __init__(self, input_file, conn: ldap.ldapobject.SimpleLDAPObject):
        self.conn = conn
        super().__init__(input_file)

    def handle(self, dn, entry):
        addthis = addModlist(entry)
        self.conn.add_s(dn, addthis)


# https://stackoverflow.com/a/29371688
def recursive_delete(conn: ldap.ldapobject.SimpleLDAPObject, base_dn: str):
    search = conn.search_s(base_dn, ldap.SCOPE_ONELEVEL)
    for dn, _ in search:
        recursive_delete(conn, dn)
    conn.delete_s(base_dn)


def save_acis(conn: ldap.ldapobject.SimpleLDAPObject, base_dn: str):
    search = conn.search_s(base_dn, ldap.SCOPE_BASE, None, ['aci'])
    return search[0][1]


@pytest.fixture(autouse=True)
def reset_database():
    with LdapConnection("cn=Directory Manager", "secret1") as conn:
        things = (
            f'ou=Groups,{SUFFIX}',
            f'ou=People,{SUFFIX}',
            f'ou=Services,{SUFFIX}'
        )

        acis = []
        for thing in things:
            try:
                acis.append(save_acis(conn, thing))
                recursive_delete(conn, thing)
            except ldap.NO_SUCH_OBJECT:
                pass

        with open('tests/everything.ldif', 'rb') as f:
            parser = MyLDIFWriter(f, conn)
            parser.parse()

        for dn, values in zip(things, acis):
            conn.modify_s(dn, ldap.modlist.modifyModlist({}, values))


class LdapConnection:
    def __init__(self, bind_dn, password):
        self.bind_dn = bind_dn
        self.password = password

    def __enter__(self):
        self.conn = ldap.initialize('ldap://ldap1.example.local:389')

        self.conn.protocol_version = ldap.VERSION3
        # l.set_option(ldap.OPT_X_TLS, 1)
        self.conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)  # TODO: change in production
        self.conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)  # This must be the last option after TLS options and is required
        self.conn.start_tls_s()
        self.conn.simple_bind_s(self.bind_dn, self.password)
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.unbind_s()


def test_deny_read_special():
    with LdapConnection(f"cn=Test,ou=Services,{SUFFIX}", "asd") as conn:
        assert True, 'Test user can connect'

        result = conn.search_s(SUFFIX, ldap.SCOPE_SUBTREE, '(objectClass=*)', ['*'])
        assert len(result) == 0, 'Test user can\'t search or view anything'


def test_deny_self_special():
    test_dn = f"cn=Test,ou=Services,{SUFFIX}"
    with LdapConnection(test_dn, "asd") as conn:
        result = conn.search_s(test_dn, ldap.SCOPE_SUBTREE, '(objectClass=*)', ['*'])
        assert len(result) == 0, 'Test user can\'t read self'

        with pytest.raises(ldap.INSUFFICIENT_ACCESS):
            conn.modify_s(test_dn, [(ldap.MOD_ADD, 'cn', b'testing that this value never appears')])


def test_deny_password_change_special():
    test_dn = f"cn=Test,ou=Services,{SUFFIX}"
    with LdapConnection(test_dn, "asd") as conn:
        with pytest.raises(ldap.INSUFFICIENT_ACCESS):
            conn.modify_s(test_dn, [(ldap.MOD_REPLACE, 'userPassword', b'asd')])


def test_allow_password_change_kc():
    with LdapConnection(f"cn=Keycloak,ou=Services,{SUFFIX}", "asd") as conn:
        conn.modify_s(f"uid=test.user,ou=People,{SUFFIX}", [
            (ldap.MOD_REPLACE, 'userPassword', b'asd')
        ])


def test_deny_password_change_kc_self():
    with LdapConnection(f"cn=Keycloak,ou=Services,{SUFFIX}", "asd") as conn:
        with pytest.raises(ldap.INSUFFICIENT_ACCESS):
            conn.modify_s(f"cn=Keycloak,ou=Services,{SUFFIX}", [
                (ldap.MOD_REPLACE, 'userPassword', b'lol')
            ])


def test_deny_password_change_kc_other():
    with LdapConnection(f"cn=Keycloak,ou=Services,{SUFFIX}", "asd") as conn:
        with pytest.raises(ldap.INSUFFICIENT_ACCESS):
            conn.modify_s(f"cn=Test,ou=Services,{SUFFIX}", [
                (ldap.MOD_REPLACE, 'userPassword', b'lol')
            ])


def test_deny_password_change_kc_ou():
    with LdapConnection(f"cn=Keycloak,ou=Services,{SUFFIX}", "asd") as conn:
        with pytest.raises(ldap.INSUFFICIENT_ACCESS):
            conn.modify_s(f"ou=Services,{SUFFIX}", [
                (ldap.MOD_REPLACE, 'userPassword', b'lol')
            ])


def test_allow_password_change_user_self():
    test_dn = f"uid=test.user,ou=People,{SUFFIX}"
    with LdapConnection(test_dn, "asd") as conn:
        conn.modify_s(test_dn, [
            (ldap.MOD_REPLACE, 'userPassword', b'asd')
        ])


def test_deny_password_change_user_other():
    with LdapConnection(f"uid=test.user,ou=People,{SUFFIX}", "asd") as conn:
        with pytest.raises(ldap.INSUFFICIENT_ACCESS):
            conn.modify_s(f"uid=test2.user2,ou=People,{SUFFIX}", [
                (ldap.MOD_REPLACE, 'userPassword', b'asd')
            ])


def test_allow_info_change_user_self():
    test_dn = f"uid=test.user,ou=People,{SUFFIX}"
    with LdapConnection(test_dn, "asd") as conn:
        conn.modify_s(test_dn, [
            (ldap.MOD_REPLACE, 'userPassword', b'asd')
        ])


def test_allow_password_change_hr():
    with LdapConnection(f"uid=test.hr,ou=People,{SUFFIX}", "asd") as conn:
        conn.modify_s(f"uid=test.user,ou=People,{SUFFIX}", [
            (ldap.MOD_REPLACE, 'userPassword', b'asd')
        ])


def test_allow_read_hr():
    with LdapConnection(f"uid=test.hr,ou=People,{SUFFIX}", "asd") as conn:
        result = conn.search_s(f"uid=test.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*'])
        assert len(result) > 0, 'User is readable'
        expected = {
            'memberOf',
            'objectClass',
            'sn',
            'mobile',
            'telegramID',
            'uid'
        }
        assert expected == set(result[0][1].keys()), 'All expected attributes are present'


def test_deny_password_read_hr():
    with LdapConnection(f"uid=test.hr,ou=People,{SUFFIX}", "asd") as conn:
        result = conn.search_s(f"uid=test.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['userPassword'])
        assert len(result[0][1]) == 0, 'No attributes returned'


def test_allow_read_kc():
    with LdapConnection(f"cn=Keycloak,ou=Services,{SUFFIX}", "asd") as conn:
        result = conn.search_s(f"uid=test.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*'])
        assert len(result) > 0, 'User is readable'
        expected = {
            'objectClass',
            'cn',
            'uid',
            'telegramID'
        }
        assert expected == set(result[0][1].keys()), 'All expected attributes are present'
