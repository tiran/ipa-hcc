# Test

## Install CA certs

```
ipa-cacert-manage install tests/ca/bundle.pem
ipa-certupdate
```

or use a `krb5.conf` snippet. The snippet has to use the realm. `libdefaults`
section does not work for me. I assume that the pkinit settings from
`krb5.conf` override the defaults `from libdefaults`.

```
cp ca/bundle.pem /etc/ipa/candlepin-bundle.pem
cp pkinit_candlepin.conf /etc/krb5.conf.d/pkinit_candlepin
```

Restart KDC

```
systemctl restart krb5kdc.service
```

## Populate test data

```
ipa-ldap-updater tests/89-testdata.update
```

## PKINIT as host

```
kinit \
    -X X509_user_identity=FILE:./tests/clients/1f84492f-a824-41b8-8ccd-a4e9e1ab2f3d.pem,./tests/clients/1f84492f-a824-41b8-8ccd-a4e9e1ab2f3d.key \
    host/hostc53b274ae54dc5dd.ipa.example
```

## References

https://bugzilla.redhat.com/show_bug.cgi?id=2075452
