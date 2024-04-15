#!/usr/bin/env python3
import argparse
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


def acis(suffix: str) -> dict[str, tuple]:
	result = dict()

	result[suffix] = (
		make_aci('Allow all to read suffix', (f'target = "ldap:///{suffix}"', 'targetattr = "objectClass"', 'targetfilter = "(objectClass=domain)"'), {'read', 'search'}, f'userdn = "ldap:///all"'),
	)

	result[f"ou=People,{suffix}"] = (
		# nsAccountLock is required to search for (!(nsAccountLock=true)), placing it in targetfilter means that it MUST be present (with the specified value).
		# mail is for password recovery
		make_aci('Allow Keycloak to read users', ('targetfilter = "(uid=*)"', 'targetattr = "objectClass || memberOf || cn || uid || mail || createTimestamp  || nsAccountLock || creatorsName || entrydn || entryid || hasSubordinates || modifiersName || modifyTimestamp || weeeOpenUniqueId || numSubordinates || parentid || subschemaSubentry"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'),
		make_aci('Allow Nextcloud to read users', ('targetfilter = "(uid=*)"', 'targetattr = "objectClass || memberOf || sn || cn || givenName || uid || mail || jpegPhoto || createTimestamp || creatorsName || entrydn || entryid || hasSubordinates || modifiersName || modifyTimestamp || weeeOpenUniqueId || numSubordinates || parentid || subschemaSubentry"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=nextcloud,ou=Services,{suffix}"'),
		# make_aci('Allow Keycloak to change OTP secrets', ('targetfilter = "(uid=*)"', 'targetattr = "otpSecretKey"'), {'write'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'),
		# make_aci('Allow users to change their password', ('targetfilter = "(uid=*)"', 'targetattr = "userPassword"'), {'write'}, f'userdn = "ldap:///self"'),
		make_aci('Allow Crauto to read users', ('targetfilter = "(uid=*)"', 'targetattr = "uid || cn || givenname || sn || memberof || mail || schacpersonaluniquecode || degreecourse || schacdateofbirth || schacplaceofbirth || mobile || safetytestdate || telegramid || telegramnickname || weeelabnickname || hasKey || signedSir || websiteDescription || pronouns || sshpublickey || description || nsaccountlock || createTimestamp || modifyTimestamp || objectClass"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),
		make_aci('Allow Crauto to edit users', ('targetfilter="(&(uid=*)(objectClass=inetOrgPerson)(objectClass=schacPersonalCharacteristics)(objectClass=schacLinkageIdentifiers)(objectClass=telegramAccount)(objectClass=weeeOpenPerson))"', 'targetattr = "objectClass || cn || givenname || sn || memberof || mail || schacpersonaluniquecode || degreecourse || schacdateofbirth || schacplaceofbirth || mobile || safetytestdate || telegramid || telegramnickname || weeelabnickname || hasKey || signedSir || websiteDescription  || pronouns || description || nsaccountlock || description"'), {'add', 'write', 'delete'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),
		make_aci('Allow Crauto to change users password', ('targetfilter = "(uid=*)"', 'targetattr = "userPassword"'), {'add', 'write'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),

		make_aci('Allow bot to read users', ('targetfilter = "(uid=*)"', 'targetattr = "uid || cn || givenname || sn || memberof || telegramid || telegramnickname || schacDateOfBirth || safetyTestDate || hasKey || signedSir || nsaccountlock || objectClass"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=bot,ou=Services,{suffix}"'),
		make_aci('Allow bot to update Telegram nickname and id', ('targetfilter = "(uid=*)"', 'targetattr = "telegramnickname || telegramid"'), {'write'}, f'userdn = "ldap:///cn=bot,ou=Services,{suffix}"'),

		make_aci('Allow Wiki to read users', ('targetfilter = "(uid=*)"', 'targetattr = "objectClass || memberOf || sn || cn || givenName || uid || mail || jpegPhoto || entrydn || weeeOpenUniqueId || nsAccountLock"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=wiki,ou=Services,{suffix}"'),

		make_aci('Allow weeehire to read users', ('targetfilter = "(uid=*)"', 'targetattr = "uid || cn || telegramnickname || nsaccountlock || memberof || objectclass"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=weeehire,ou=Services,{suffix}"'),

		make_aci('Allow weeelab to read users', ('targetfilter = "(uid=*)"', 'targetattr = "uid || givenname || cn || schacpersonaluniquecode || weeelabnickname || signedsir || nsaccountlock || objectClass"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=weeelab,ou=Services,{suffix}"'),
	)

	result[f"ou=Invites,{suffix}"] = (
		make_aci('Allow Crauto to read invites', ('targetfilter = "(cn=*)"', 'targetattr = "inviteCode || cn || givenname || sn || mail || schacpersonaluniquecode || degreecourse || telegramid || telegramnickname"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),
		make_aci('Allow Crauto to delete invites', ('targetfilter = "(cn=*)"',), {'delete'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),

		make_aci('Allow weeehire to read and create invites', ('targetfilter = "(cn=*)"', 'targetattr = "inviteCode || cn || givenname || sn || mail || schacpersonaluniquecode || degreecourse"'), {'read', 'search', 'compare', 'write', 'add'}, f'userdn = "ldap:///cn=weeehire,ou=Services,{suffix}"'),

		make_aci('Allow Bot to read invites', ('targetattr = "inviteCode || telegramid || telegramnickname"',), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=bot,ou=Services,{suffix}"'),
		make_aci('Allow Bot to update invites', ('targetattr = "telegramid || telegramnickname"',), {'write'}, f'userdn = "ldap:///cn=bot,ou=Services,{suffix}"'),
	)

	result[f"ou=Groups,{suffix}"] = (
		make_aci('Allow Keycloak to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || weeeOpenUniqueId"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Keycloak,ou=Services,{suffix}"'),
		make_aci('Allow Nextcloud to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || weeeOpenUniqueId"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=Nextcloud,ou=Services,{suffix}"'),
		make_aci('Allow Wiki to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || member || uniqueMember || weeeOpenUniqueId"'), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=wiki,ou=Services,{suffix}"'),
		make_aci('Allow Crauto to read groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || weeeOpenUniqueId"',), {'read', 'search', 'compare'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),
		make_aci('Allow Crauto to add and remove people from groups', ('targetfilter = "(cn=*)"', 'targetattr = "member || uniqueMember"',), {'write'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),
	)

	result[f"ou=Machines,{suffix}"] = (
		make_aci('Allow Crauto to manage groups', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || createTimestamp || modifyTimestamp"',), {'read', 'search', 'compare', 'write', 'add'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),
		make_aci('Allow machines to read their data', ('targetfilter = "(cn=*)"', 'targetattr = "objectClass || cn || ou || description || member || uniqueMember || createTimestamp || modifyTimestamp"',), {'read', 'search', 'compare'}, f'userdn = "ldap:///self"'),
		# make_aci('Allow Crauto to change machine accounts password', ('targetfilter = "(cn=*)"', 'targetattr = "userPassword"'), {'add', 'write'}, f'userdn = "ldap:///cn=crauto,ou=Services,{suffix}"'),
	)

	return result


def yaml(suffix: str):
	things: dict[str, tuple] = acis(suffix)

	print("Paste this into your playbook:\n")
	for dn in things:
		print(f"""      -
		        dn: "{dn}"
		        acis:""")
		for aci in things[dn]:
			print_aci(aci)


def ldif(suffix: str):
	things: dict[str, tuple] = acis(suffix)

	for dn in things:
		print(f"dn: {dn}\n\
changetype: modify\n\
replace: aci")
		for aci in things[dn]:
			print(f"aci: {aci}")
		print("")


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-y", "--yaml", action="store_true")
	group.add_argument("-l", "--ldif", action="store_true")
	parser.add_argument('-s', '--suffix', help='Directory suffix or a variable that will be substituted, e.g. dc=example,dc=com or {{ dirsrv_suffix }}', required=True)
	args = parser.parse_args()

	if args.yaml:
		yaml(args.suffix)
	else:
		ldif(args.suffix)
