#!/usr/bin/env python3

from typing import Iterable

# There's also lib389: https://lib389.readthedocs.io/en/latest/
# but it's more focused on writing tests for 389DS itself, I couldn't find anything useful there...


def make_aci(name: str, targets: Iterable[str], permissions: Iterable[str], subject: str):
	# Administration Guide, section 18.3, general structure of an ACI:
	# (target_rule) (version 3.0; acl "ACL_name"; permission_rule bind_rules;)
	permission_rule = ', '.join(permissions)
	target = '(' + ')('.join(targets) + ')'

	rule = f'version 3.0; acl "{name}"; allow ({permission_rule}) {subject};'

	return f'{target} ({rule})'


def print_aci(aci: str):
	print(f"          - '{aci}'")


def acis():
	suffix = 'dc=example,dc=local'
	# suffix = '{{ suffix }}'

	print("Paste this into your playbook:")
	print(f"""      -
        dn: "{suffix}"
        acis:""")
	print_aci(make_aci('Allow all to read suffix', ('target = "ldap:///{suffix}"', 'targetattr = "objectClass"'), {'read', 'search'}, f'userdn = "ldap:///all"'))
	print(f"""      -
        dn: "ou=People,{suffix}"
        acis:""")
	print_aci(make_aci('Allow Keycloak to read users', ('targetfilter = "(uid=*)"', 'targetattr = "objectClass || cn || uid || telegramID || createTimestamp || creatorsName || entrydn || entryid || hasSubordinates || modifiersName || modifyTimestamp || nsUniqueId || numSubordinates || parentid || subschemaSubentry"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Keycloak to change passwords', ('targetfilter = "(uid=*)"', 'targetattr = "userPassword"'), {'write'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow users to change their password', ('targetfilter = "(uid=*)"', 'targetattr = "userPassword"'), {'write'}, f'userdn = "ldap:///self"'))
	print_aci(make_aci('Allow HR to read and edit users', ('targetfilter = "(uid=*)"', 'targetattr = "objectClass || uid || sn || schacPersonalUniqueCode || degreeCourse || schacDateOfBirth || schacPlaceOfBirth || mobile || mail || safetyTestDate || telegramID || telegramNickname || description"'), {'add', 'read', 'write', 'search', 'compare'}, f'groupdn = "ldap:///cn=HR,ou=Groups,{suffix}"'))
	print_aci(make_aci('Allow HR to change users password', ('targetfilter = "(uid=*)"', 'targetattr = "userPassword"'), {'write'}, f'groupdn = "ldap:///cn=HR,ou=Groups,{suffix}"'))
	print_aci(make_aci('Allow HR to add and remove users', ('targetfilter = "(uid=*)"',), {'add', 'delete'}, f'groupdn = "ldap:///cn=HR,ou=Groups,{suffix}"'))
	print_aci(make_aci('Allow HR to read user groups via memberOf', ('targetfilter = "(uid=*)"', 'targetattr = "memberOf"'), {'read', 'search', 'compare'}, f'groupdn = "ldap:///cn=HR,ou=Groups,{suffix}"'))

	print(f"""      -
        dn: "ou=Groups,{suffix}"
        acis:""")
	print_aci(make_aci('Allow Keycloak to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember  || createTimestamp || creatorsName || entrydn || entryid || hasSubordinates || modifiersName || modifyTimestamp || nsUniqueId || numSubordinates || parentid || subschemaSubentry"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow HR to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember"',), {'read', 'search', 'compare'}, f'groupdn = "ldap:///cn=HR,ou=Groups,{suffix}"'))
	print_aci(make_aci('Allow HR to add and remove people from groups', ('targetfilter = "(cn=*)"', 'targetattr = "member || uniqueMember"',), {'write'}, f'groupdn = "ldap:///cn=HR,ou=Groups,{suffix}"'))


if __name__ == '__main__':
	acis()
