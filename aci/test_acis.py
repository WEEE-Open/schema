#!/usr/bin/env python3

import ldap
import ldif
from ldap.modlist import addModlist
import pytest


SUFFIX = 'dc=sso,dc=local'


class MyLDIFWriter(ldif.LDIFParser):
	def __init__(self, input_file, conn: ldap.ldapobject.SimpleLDAPObject):
		self.conn = conn
		super().__init__(input_file)

	def handle(self, dn, entry):
		addthis = addModlist(entry)
		self.conn.add_s(dn, addthis)


def recursive_delete_subtree(conn: ldap.ldapobject.SimpleLDAPObject, base_dn: str):
	search = conn.search_s(base_dn, ldap.SCOPE_ONELEVEL)
	for dn, _ in search:
		recursive_delete(conn, dn)


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

		# acis = []
		for thing in things:
			try:
				# acis.append(save_acis(conn, thing))
				recursive_delete_subtree(conn, thing)
			except ldap.NO_SUCH_OBJECT:
				pass

		with open('tests/everything.ldif', 'rb') as f:
			parser = MyLDIFWriter(f, conn)
			parser.parse()

		# for dn, values in zip(things, acis):
		# 	conn.modify_s(dn, ldap.modlist.modifyModlist({}, values))


@pytest.fixture()
def example_user():
	return [
		('objectClass',
		 [b'telegramAccount', b'schacPersonalCharacteristics', b'top', b'person', b'organizationalPerson',
		  b'inetOrgPerson', b'weeeOpenPerson']),
		('cn', [b'Example User']),
		('sn', [b'User']),
		('mobile', [b'+39010101011011']),
		('telegramID', [b'1337']),
		('uid', [b'example.user'])
	]


@pytest.fixture()
def example_user_with_password(example_user):
	example_user.append(('userPassword', [b'{PBKDF2_SHA256}AAAnENBOg9Pr7VfWGJEKpYaCNCvCTpe8xZAeCkcneca7Gir'
								b'KbHwLQ24j9I7u2c1vXSPnsWZzd4OoKETdAJZzxUhFJvlqBI7P71M7ts+t9QHJoo4Yx5TcSOCoz2'
								b'zNGtnjlQqi+rptAG5yNmiYJ1jULvXPHkNtr6Ckkwr3SgcpKWpJDLGLXNuhJkww/jv7D0eC/I9jz'
								b'nkOO5lJwMBKmxuWwxLjFjJ7MK1YGFPpUkxZuam3iy2X6kmPEQXCZdhE9dgATjK5I2WlgQOAZ34H'
								b'ouJHxuzV83JG+SJnYpE5rzDfuSmhaCZfmwWQpZCPNU1QKx+CrAeUht/Vrk4iM7ScJM+si/eTOaK'
								b'OCVGvpr2xZEvIy0xOXTAF6UW5Acos1a8jtKBJf4zmlsfKGByXQPNj38bd6CyVdKie1R6OT+YtPN'
								b'EkmrcSJCNc']))
	return example_user


@pytest.fixture()
def example_group():
	return [
		('objectClass', [b'top', b'organizationalunit']),
		('cn', [b'Example Group'])
	]


@pytest.fixture()
def empty_container():
	return [
		('objectClass', [b'top', b'inetOrgPerson']),
		('cn', [b'Empty'])
	]


class LdapConnection:
	def __init__(self, bind_dn, password):
		self.bind_dn = bind_dn
		self.password = password

	def __enter__(self):
		self.conn = ldap.initialize('ldap://ldap1.sso.local:389')

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
		for dn, attributes in result:
			assert set(attributes.keys()) == {'objectClass'}, 'Only objectClass is returned'


def test_deny_self_special():
	test_dn = f"cn=Test,ou=Services,{SUFFIX}"
	with LdapConnection(test_dn, "asd") as conn:
		result = conn.search_s(test_dn, ldap.SCOPE_SUBTREE, '(objectClass=*)', ['*'])
		for dn, attributes in result:
			assert set(attributes.keys()) == {'objectClass'}, 'Only objectClass is returned'

		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(test_dn, [(ldap.MOD_ADD, 'cn', b'testing that this value never appears')])


# Crauto can change passwords
@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}"])
def test_allow_password_change(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		conn.modify_s(f"uid=test.user,ou=People,{SUFFIX}", [
			(ldap.MOD_REPLACE, 'userPassword', b'asdasdasdasdasdasd')
		])


# Those who can change passwords, can't replace them with passwords that violate constraints
@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}"])
def test_fail_password_change_constraint(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.CONSTRAINT_VIOLATION):
			conn.modify_s(f"uid=test.user,ou=People,{SUFFIX}", [
				(ldap.MOD_REPLACE, 'userPassword', b'a')
			])


@pytest.mark.parametrize("bind_dn", [f"uid=test2.user2,ou=People,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}"])
def test_deny_password_change(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(f"uid=test.user,ou=People,{SUFFIX}", [
				(ldap.MOD_REPLACE, 'userPassword', b'asdasdasdasdasdasd')
			])


@pytest.mark.parametrize("bind_dn", [f"uid=test.user,ou=People,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}"])
def test_deny_password_change_sso_service(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(f"cn=Keycloak,ou=Services,{SUFFIX}", [
				(ldap.MOD_REPLACE, 'userPassword', b'lol')
			])


@pytest.mark.parametrize("bind_dn", [f"uid=test.user,ou=People,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}"])
def test_deny_password_change_service(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(f"cn=Test,ou=Services,{SUFFIX}", [
				(ldap.MOD_REPLACE, 'userPassword', b'lol')
			])


@pytest.mark.parametrize("bind_dn", [f"uid=test.user,ou=People,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}"])
def test_deny_password_change_ou(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(f"ou=Services,{SUFFIX}", [
				(ldap.MOD_REPLACE, 'userPassword', b'lol')
			])


@pytest.mark.parametrize("bind_dn", [f"uid=test.user,ou=People,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}"])
def test_deny_info_change_user(bind_dn):
	test_dn = f"uid=test.user,ou=People,{SUFFIX}"
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(test_dn, [
				(ldap.MOD_REPLACE, 'mobile', b'+392222222')
			])


def test_allow_info_change_crauto():
	test_dn = f"uid=test.user,ou=People,{SUFFIX}"
	value = b'+392222222'
	with LdapConnection(f"cn=Crauto,ou=Services,{SUFFIX}", "asd") as conn:
		conn.modify_s(test_dn, [(ldap.MOD_REPLACE, 'mobile', value)])
		result = conn.search_s(test_dn, ldap.SCOPE_BASE, None, ['mobile'])
		assert len(result) > 0, 'mobile exists'
		assert result[0][1]['mobile'][0] == value, 'mobile has the expected value'


def test_allow_read_crauto():
	with LdapConnection(f"cn=Crauto,ou=Services,{SUFFIX}", "asd") as conn:
		result = conn.search_s(f"uid=test.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*', '+'])
		assert len(result) > 0, 'User is readable'
		expected = {
			'memberOf',
			'objectClass',
			'givenName',
			'mail',
			'cn',
			'sn',
			'mobile',
			'telegramID',
			'uid',
			'createTimestamp',
			'modifyTimestamp',
		}
		assert expected == set(result[0][1].keys()), 'All expected attributes are present'


def test_allow_read_nextcloud():
	with LdapConnection(f"cn=Nextcloud,ou=Services,{SUFFIX}", "asd") as conn:
		result = conn.search_s(f"uid=test.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*', '+'])
		assert len(result) > 0, 'User is readable'
		expected = {
			'memberOf',
			'objectClass',
			'cn',
			'sn',
			'givenName',
			'uid',
			'mail',
			'entryid',
			'nsUniqueId',
			'createTimestamp',
			'modifyTimestamp',
			'creatorsName',
			'modifiersName',
			'parentid',
			'entrydn',
		}
		assert expected == set(result[0][1].keys()), 'All expected attributes are present'


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}"])
def test_deny_password_read(bind_dn):
	with LdapConnection(f"cn=Crauto,ou=Services,{SUFFIX}", "asd") as conn:
		result = conn.search_s(bind_dn, ldap.SCOPE_BASE, None, ['userPassword'])
		assert len(result[0][1]) == 0, 'No attributes returned'


def test_allow_read_sso():
	with LdapConnection(f"cn=Keycloak,ou=Services,{SUFFIX}", "asd") as conn:
		result = conn.search_s(f"uid=test.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*', '+'])
		assert len(result) > 0, 'User is readable'
		expected = {
			'modifyTimestamp',
			'modifiersName',
			'memberOf',
			'objectClass',
			'cn',
			'uid',
			'creatorsName',
			'createTimestamp',
			'nsUniqueId',
			'parentid',
			'entryid',
			'entrydn',
		}
		assert expected == set(result[0][1].keys()), 'All expected attributes are present'


@pytest.mark.parametrize("bind_dn", [f"cn=Keycloak,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}"])
def test_deny_add_user(bind_dn, example_user):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.add_s(f"uid=example.user,ou=People,{SUFFIX}", example_user)


def test_allow_add_user_crauto(example_user):
	with LdapConnection(f"cn=Crauto,ou=Services,{SUFFIX}", "asd") as conn:
		conn.add_s(f"uid=example.user,ou=People,{SUFFIX}", example_user)
		result = conn.search_s(f"uid=example.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*'])
		assert len(result) > 0, 'User has been added'


@pytest.mark.parametrize("bind_dn", [f"cn=Keycloak,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}"])
def test_deny_delete_user(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.delete_s(f"uid=test2.user2,ou=People,{SUFFIX}")


def test_allow_delete_user_crauto():
	with LdapConnection(f"cn=Crauto,ou=Services,{SUFFIX}", "asd") as conn:
		conn.delete_s(f"uid=test2.user2,ou=People,{SUFFIX}")
		result = conn.search_s(f"uid=test2.user2,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*'])
		assert len(result) == 0, 'User is gone'


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}"])
def test_deny_add_group(bind_dn, example_group):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.add_s(f"cn=Example Group,ou=Groups,{SUFFIX}", example_group)


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}"])
def test_deny_delete_group(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.delete_s(f"cn=People,ou=Groups,{SUFFIX}")


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}"])
def test_deny_add_container(bind_dn, empty_container):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.add_s(f"cn=Empty,{SUFFIX}", empty_container)


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}", f"uid=test.hr,ou=People,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}"])
def test_deny_delete_container(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.delete_s(f"ou=People,{SUFFIX}")


@pytest.mark.parametrize("bind_dn", [f"cn=Test,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}"])
def test_deny_read_group(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		result = conn.search_s(f"cn=Testers,ou=Groups,{SUFFIX}", ldap.SCOPE_BASE, None, ['ou', 'member'])
		assert len(result[0][1]) == 0, 'No group details or members are visible'


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}", f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}"])
def test_allow_read_group(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		result = conn.search_s(f"cn=Testers,ou=Groups,{SUFFIX}", ldap.SCOPE_BASE, None, ['ou', 'member'])
		attributes = result[0][1]
		assert len(attributes) > 0, 'Some attributes are found'
		assert 'ou' in attributes, 'ou is readable'
		assert 'member' in attributes, 'member is readable'
		assert len(attributes['member']) > 0, 'Groups has some members'


@pytest.mark.parametrize("bind_dn", [f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}"])
def test_deny_add_to_group(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(f"cn=Testers,ou=Groups,{SUFFIX}", [(ldap.MOD_ADD, 'member', bytes(f'uid=test.hr,ou=People,{SUFFIX}', 'utf8'))])


@pytest.mark.parametrize("bind_dn", [f"cn=Keycloak,ou=Services,{SUFFIX}", f"cn=Test,ou=Services,{SUFFIX}", f"cn=Nextcloud,ou=Services,{SUFFIX}", f"uid=test.user,ou=People,{SUFFIX}"])
def test_deny_remove_from_group(bind_dn):
	with LdapConnection(bind_dn, "asd") as conn:
		with pytest.raises(ldap.INSUFFICIENT_ACCESS):
			conn.modify_s(f"cn=Testers,ou=Groups,{SUFFIX}", [(ldap.MOD_DELETE, 'member', bytes(f'uid=test.user,ou=People,{SUFFIX}', 'utf8'))])


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}"])
def test_allow_add_to_group(bind_dn):
	target = f'uid=test.hr,ou=People,{SUFFIX}'
	group = f"cn=Testers,ou=Groups,{SUFFIX}"

	target_b = bytes(target, 'utf8')
	group_b = bytes(group, 'utf8')
	with LdapConnection(bind_dn, "asd") as conn:
		result = conn.search_s(group, ldap.SCOPE_BASE, None, ['member'])
		assert target_b not in result[0][1]['member'], 'User is not yet member in group'

		result = conn.search_s(target, ldap.SCOPE_BASE, None, ['memberOf'])
		assert 'memberOf' not in result[0][1] or group_b not in result[0][1]['memberOf'], 'User doesn\'t have memberOf attribute yet'

		conn.modify_s(group, [(ldap.MOD_ADD, 'member', bytes(target, 'utf8'))])

		result = conn.search_s(group, ldap.SCOPE_BASE, None, ['member'])
		assert target_b in result[0][1]['member'], 'User is member in group'

		result = conn.search_s(target, ldap.SCOPE_BASE, None, ['memberOf'])
		assert group_b in result[0][1]['memberOf'], 'User has memberOf attribute'


@pytest.mark.parametrize("bind_dn", [f"cn=Crauto,ou=Services,{SUFFIX}"])
def test_allow_remove_to_group(bind_dn):
	target = f'uid=test.user,ou=People,{SUFFIX}'
	group = f"cn=Testers,ou=Groups,{SUFFIX}"

	target_b = bytes(target, 'utf8')
	group_b = bytes(group, 'utf8')
	with LdapConnection(bind_dn, "asd") as conn:
		result = conn.search_s(group, ldap.SCOPE_BASE, None, ['member'])
		assert target_b in result[0][1]['member'], 'User is member in group'

		result = conn.search_s(target, ldap.SCOPE_BASE, None, ['memberOf'])
		assert group_b in result[0][1]['memberOf'], 'User has memberOf attribute'

		conn.modify_s(group, [(ldap.MOD_DELETE, 'member', bytes(target, 'utf8'))])

		result = conn.search_s(group, ldap.SCOPE_BASE, None, ['member'])
		assert target_b not in result[0][1]['member'], 'User is no longer member in group'

		result = conn.search_s(target, ldap.SCOPE_BASE, None, ['memberOf'])
		assert 'memberOf' not in result[0][1] or group_b not in result[0][1]['memberOf'], 'User doesn\'t have memberOf anymore'


def test_password_lockout(example_user_with_password):
	with LdapConnection(f"cn=Directory Manager", "secret1") as conn:
		conn.add_s(f"uid=example.user,ou=People,{SUFFIX}", example_user_with_password)
		result = conn.search_s(f"uid=example.user,ou=People,{SUFFIX}", ldap.SCOPE_BASE, None, ['*'])
		assert len(result) > 0, 'User has been added'

	attempts = 0
	with pytest.raises(ldap.CONSTRAINT_VIOLATION):
		for i in range(1, 20):
			try:
				with LdapConnection(f"uid=example.user,ou=People,{SUFFIX}", "invalid"):
					pass
			except ldap.INVALID_CREDENTIALS:
				attempts += 1
	assert attempts == 5, 'Failure after 5 attempts'
