# Container images for CI

## Rebuild steps

Rebuild the SRPM for current distro, so the SRPM has correct build
dependencies for current distro.

```
rpmbuild -rs path/to/ipa-hcc*.src.rpm
```

Install build dependencies (should be pre-installed)

```
yum-builddep -y path/to/SRPMS/ipa-hcc*.src.rpm
```

Build binaries

```
rpmbuild -rb path/to/SRPMS/ipa-hcc*.src.rpm
```

Create repo

```
createrepo path/to/RPMS/
```
