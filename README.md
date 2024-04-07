# WEEE Open LDAP schema

Some LDAP schema files that we use. Everything is in a format compatible with 389DS and can be readily dropped into `/etc/dirsrv/slapd-.../schema`.

License is inside each file, except for [SCHAC](https://wiki.refeds.org/display/STAN/SCHAC+Releases) for which I couldn't locate a license.

### SCHAC

SCHema for ACademia.

The file `97schac.ldif` comes from the [official schema](https://wiki.refeds.org/display/STAN/SCHAC+Releases) in OpenLDAP format, converted to 389DS format with manual edits (replacing textual OIDs with numbers from olcObjectIdentifier) and [some scripts](https://directory.fedoraproject.org/docs/389ds/howto/howto-openldapmigration.html), especially ol2rhds.pl.

### SSH

Located at `98ssh.ldif`, it allows storing public SSH keys. It's an OpenLDAP schema with minor modifications to adapt it to 389DS.

### Telegram

`98telegram.ldif` is a simple schema to store some [Telegram](https://telegram.org/) related inforamation: ID, nickname and group invite links.

The very large OID from the UUID arc (i.e. `2.25.100841824846419382782883384063386193490`) may cause some problems to very old/buggy software, however both 389DS and Apache Directory Studio seem to have no problems with them.

### WEEE Open

There are a few more bits and bobs in `98weeeopen.ldif`. Not very interesting.

## Password Policies

Use `policies.yml` to replace existing values.

## ACI

The `aci` directory contains some ACIs for 389DS and tests related to those.

`make_acis.py` has a method that formats all the parts into an ACI, then it prints all the ACIs in a YAML format that can be
pasted into an Ansible playbook. For details on how and where to paste it, see
[the "sso" repo](https://github.com/WEEE-Open/sso).

Alternatively, `make_acis.py` can also output a LDIF file.

`test_acis.py` uses pytest to test that the ACIs are working as expected. It also tests the password policy set in
[the "sso" repo](https://github.com/WEEE-Open/sso). It requires 389DS configured as in that repo. If you follow the
instructions there, you'll clone this repo anyway, so it all makes sense, hopefully.

The workflow for making ACIs and testing should be something like this:

```shell
cd aci
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# For Ansible, past the output into the playbook:
./make_acis.py -y -s "{{ dirsrv_suffix }}"
# Alternatively, as a LDIF file (replace with real suffix):
./make_acis.py -l -s "dc=example,dc=test"
# Create LDIF file with ACIs for tests:
./make_acis.py -l -s "dc=example,dc=test" > aci_tmp.ldif
# Required env variables for the tests
export TEST_PASSWORD="secret1"
export TEST_LDAP_CONNECTION_STRING="ldap://ldap1.sso.local:389"
export TEST_SUFFIX="dc=example,dc=test"
export TEST_ACI_LDIF="aci_tmp.txt"
export TEST_IMPORT_SCHEMA=1 # To import the schema during tests, do not set at all if you want to import manually
# Run tests
./test_acis.py
# Watch test output
```
