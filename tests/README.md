# Test

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
