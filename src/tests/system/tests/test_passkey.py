"""
Passkey Tests.

:requirement: passkey
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.builtwith(client="passkey")
@pytest.mark.topology(KnownTopology.Client)
def test_passkey__register__sssctl(client: Client, moduledatadir: str, testdatadir: str):
    """
    :title: Register a key with sssctl
    :setup:
        1. Setup IDM client with FIDO and umockdev setup
    :steps:
        1. Use sssctl to register a FIDO2 key.
        2. Check the output.
    :expectedresults:
        1. New key is registered
        2. Output contains key mapping data.
    :customerscenario: False
    """
    mapping = client.sssctl.passkey_register(
        username="user1",
        domain="ldap.test",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script",
    )

    with open(f"{testdatadir}/passkey-mapping") as f:
        assert mapping == f.read().strip(), "Failed to register a key with sssctl"


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_passkey__register__ipa(ipa: IPA, moduledatadir: str, testdatadir: str):
    """
    :title: Register a passkey with the IPA command
    :setup:
        1. Setup IDM client with FIDO and umockdev setup
    :steps:
        1. Use ipa command to register a FIDO2 key.
        2. Check the output that contains the user key mapping data.
    :expectedresults:
        1. New key is registered with IPA command.
        2. Output contains key mapping data.
    :customerscenario: False
    """
    mapping = (
        ipa.user("user1")
        .add()
        .passkey_add_register(
            pin=123456,
            device=f"{moduledatadir}/umockdev.device",
            ioctl=f"{moduledatadir}/umockdev.ioctl",
            script=f"{testdatadir}/umockdev.script",
        )
    )

    with open(f"{testdatadir}/passkey-mapping") as f:
        assert mapping == f.read().strip(), "Failed to register a key with the IPA command"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.builtwith(client="passkey", provider="passkey")
def test_passkey__su(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
    """
    :title: Check authentication of user with LDAP, IPA, AD and Samba
    :setup:
        1. Add a user in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user.
    :expectedresults:
        1. User authenticates successfully.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    if suffix == "ldap":
        client.sssd.domain["local_auth_policy"] = "only"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.LDAP, ldap="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_passkey__su_fail_pin(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
    """
    :title: Check authentication deny of user with LDAP, IPA, AD and Samba with incorrect pin
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user with incorrect PIN.
    :expectedresults:
        1. User failed to authenticate.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    if suffix == "ldap":
        client.sssd.domain["local_auth_policy"] = "only"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert not client.auth.su.passkey(
        username="user1",
        pin=67890,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.LDAP, ldap="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_passkey__su_fail_mapping(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
    """
    :title: Check authentication deny of user with LDAP, IPA, AD and Samba with incorrect mapping
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user with incorrect passkey mapping.
    :expectedresults:
        1. User failed to authenticate.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    if suffix == "ldap":
        client.sssd.domain["local_auth_policy"] = "only"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert not client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.LDAP, ldap="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_passkey__su_srv_not_resolvable(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check authentication of a user with LDAP, IPA, AD and Samba when server is not resolvable
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user.
        2. Update the server url and restart the sssd service to reflect the changes.
        3. Check authentication of the user.
    :expectedresults:
        1. User authenticates successfully.
        2. Successfully update the sssd.conf and restarted the sssd service.
        3. User authenticates successfully due to cached data.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()
    if suffix == "ipa":
        server_url = "ipa_server"
    elif suffix == "ldap":
        server_url = "ldap_uri"
        client.sssd.domain["local_auth_policy"] = "only"
    elif suffix == "samba" or "ad":
        server_url = "ad_server"
    else:
        assert False, "provider not found"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    # First time check authentication to cache the user
    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

    # Here we are making server/backend offline but not deleting cache and logs.
    client.sssd.config.remove_option("domain/test", server_url)
    client.sssd.domain[server_url] = "ldap://new.server.test"
    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.LDAP, ldap="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_passkey__offline_su(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
    """
    :title: Check offline authentication of a user with LDAP, IPA, AD and Samba
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. In SSSD domain change "cache_credentials" and "krb5_store_password_if_offline" to "True"
        3. In SSSD pam change "offline_credentials_expiration" to "0"
        4. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user.
        2. Make server offline by removing rules for LDAP, KDC and Global Catalog ports.
        3. Bring SSSD is offline explicitly.
        4. Check offline authentication of the user.
    :expectedresults:
        1. User authenticated successfully.
        2. Firewall rules dropped.
        3. SSSD is offline.
        4. Offline authentication is successful.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    if suffix == "ldap":
        client.sssd.domain["local_auth_policy"] = "only"

    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"

    client.sssd.start()

    # First time check authentication to cache the user
    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

    # Block KDC, LDAP and Global Catalog ports.
    provider.firewall.drop([88, 389, 3268])

    # There might be active connections that are not terminated by creating firewall rule.
    # We need to terminated it by bringing SSSD to offline state explicitly.
    client.sssd.bring_offline()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.LDAP, ldap="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_passkey__user_fetch_from_cache(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Fetch user from cache for LDAP, IPA, AD and Samba server
    :setup:
        1. Add a user in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check user lookup.
        2. Check user from cache using ldbsearch command.
    :expectedresults:
        1. User looked up successfully.
        2. Successfully get the user from ldbsearch command.
    :customerscenario: False
    """

    suffix = type(provider).__name__.lower()

    if suffix == "ldap":
        client.sssd.domain["local_auth_policy"] = "only"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    result = client.tools.id("user1")
    ldb_search = client.ldb.search(path="/var/lib/sss/db/cache_test.ldb", basedn="cn=test,cn=sysdb")
    assert result is not None
    assert "user1" in ldb_search


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.LDAP, ldap="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_passkey__su_multi_keys_for_same_user(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check authentication of user when multiple keys added for same user with
            LDAP, IPA, AD and Samba server.
    :setup:
        1. Add a user with multiple mappings of passkey in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user.
    :expectedresults:
        1. User authenticates successfully.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()
    user_add = provider.user("user1").add()

    if suffix == "ldap":
        client.sssd.domain["local_auth_policy"] = "only"
        for n in range(1, 5):
            if bool(user_add.get(attrs=["passkey"])):
                with open(f"{testdatadir}/passkey-mapping.{suffix}{n}") as f:
                    attrs = {"passkey": f.read().strip()}
                    user_add._modify(add=attrs)
            else:
                with open(f"{testdatadir}/passkey-mapping.{suffix}{n}") as f:
                    user_add.passkey_add(f.read().strip())
    else:
        for n in range(1, 5):
            with open(f"{testdatadir}/passkey-mapping.{suffix}{n}") as f:
                user_add.passkey_add(f.read().strip())

    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.builtwith(client="passkey")
@pytest.mark.builtwith(KnownTopology.LDAP, ldap="passkey")
@pytest.mark.builtwith(KnownTopology.IPA, ipa="passkey")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_passkey__su_same_key_for_multi_user(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check authentication of user when same key added for multiplr user with LDAP, IPA, AD and Samba server.
    :setup:
        1. Add three users with same passkey mapping in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user1, user2 and user3.
    :expectedresults:
        1. User1, user2 and user3 authenticates successfully with same mapping.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    if suffix == "ldap":
        client.sssd.domain["local_auth_policy"] = "only"

    for user in ["user1", "user2", "user3"]:
        user_add = provider.user(user).add()
        with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
            user_add.passkey_add(f.read().strip())

        client.sssd.start()

        assert client.auth.su.passkey(
            username=user,
            pin=123456,
            device=f"{moduledatadir}/umockdev.device",
            ioctl=f"{moduledatadir}/umockdev.ioctl",
            script=f"{testdatadir}/umockdev.script.{suffix}.{user}",
        )
