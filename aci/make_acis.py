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
	# suffix = 'dc=example,dc=local'
	suffix = '{{ dirsrv_suffix }}'

	print("Paste this into your playbook:\n")
	print(f"""      -
        dn: "{suffix}"
        acis:""")
	# Apparently, avoiding disclosure ("does this DN exist or not?") is impossible, so it's not worth it to try to hide
	# entries that shouldn't be seen e.g. in ou=Services. Authorized accounts will know which other accounts exist and
	# their objectClass, but that doesn't seem an extreme security risk to me...
	print_aci(make_aci('Allow all to read suffix', (f'target = "ldap:///{suffix}"', 'targetattr = "objectClass"'), {'read', 'search'}, f'userdn = "ldap:///all"'))
	print(f"""      -
        dn: "ou=People,{suffix}"
        acis:""")
	print_aci(make_aci('Allow Keycloak to read users', ('targetfilter = "(uid=*)"', 'targetattr = "objectClass || memberOf || cn || uid || otpSecretKey || createTimestamp || creatorsName || entrydn || entryid || hasSubordinates || modifiersName || modifyTimestamp || nsUniqueId || numSubordinates || parentid || subschemaSubentry"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Nextcloud to read users', ('targetfilter = "(uid=*)"', 'targetattr = "objectClass || memberOf || sn || cn || givenName || uid || mail || jpegPhoto || createTimestamp || creatorsName || entrydn || entryid || hasSubordinates || modifiersName || modifyTimestamp || nsUniqueId || numSubordinates || parentid || subschemaSubentry"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=nextcloud,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Keycloak to change OTP secrets', ('targetfilter = "(uid=*)"', 'targetattr = "otpSecretKey"'), {'write'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'))
	# print_aci(make_aci('Allow users to change their password', ('targetfilter = "(uid=*)"', 'targetattr = "userPassword"'), {'write'}, f'userdn = "ldap:///self"'))

	print_aci(make_aci('Allow Crauto to read users', ('targetfilter = "(uid=*)"', 'targetattr = "uid || cn || givenname || sn || memberof || mail || schacpersonaluniquecode || degreecourse || schacdateofbirth || schacplaceofbirth || mobile || safetytestdate || telegramid || telegramnickname || sshpublickey || description || nsaccountlock || createTimestamp || modifyTimestamp || objectClass"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Crauto to edit users', ('targetfilter="(&(uid=*)(objectClass=inetOrgPerson)(objectClass=schacPersonalCharacteristics)(objectClass=schacLinkageIdentifiers)(objectClass=telegramAccount)(objectClass=weeeOpenPerson))"', 'targetattr = "objectClass || cn || givenname || sn || memberof || mail || schacpersonaluniquecode || degreecourse || schacdateofbirth || schacplaceofbirth || mobile || safetytestdate || telegramid || telegramnickname || description || nsaccountlock || description"'), {'add', 'write', 'delete'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Crauto to change users password', ('targetfilter = "(uid=*)"', 'targetattr = "userPassword"'), {'add', 'write'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'))
	print(f"""      -
        dn: "ou=Invites,{suffix}"
        acis:""")
	print_aci(make_aci('Allow Crauto to read invites', ('targetfilter = "(cn=*)"', 'targetattr = "inviteCode || cn || givenname || sn || mail || schacpersonaluniquecode || degreecourse || telegramid || telegramnickname"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Crauto to delete invites', ('targetfilter = "(cn=*)"',), {'delete'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'))

	print(f"""      -
        dn: "ou=Groups,{suffix}"
        acis:""")
	print_aci(make_aci('Allow Keycloak to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || nsUniqueId"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Nextcloud to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || nsUniqueId"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Nextcloud,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Crauto to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || nsUniqueId"',), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'))
	print_aci(make_aci('Allow Crauto to add and remove people from groups', ('targetfilter = "(cn=*)"', 'targetattr = "member || uniqueMember"',), {'write'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'))


if __name__ == '__main__':
	acis()
