# Continuous Integration with idm-ci

## Supported OS

- rhel-7.9 (latest z-stream)
- rhel-8.6 (*)
- rhel-8.7
- rhel-8.8 (dev)
- rhel-9.0
- rhel-9.1
- rhel-9.2 (dev)

Kerberos KDC on RHEL 8.6 server uses SHA-1 for PKINIT, which is incompatible
with RHEL 9's crypto policy.

## Production

Create activation key at https://access.redhat.com/management/activation_keys
Create RHSM API token at https://access.redhat.com/management/api

See https://access.redhat.com/articles/3626371

If your account cannot access Insights, then it might miss the EBS
number. Contact RH customer support to add an EBS number to an account.

## Stage

Create account: https://account-manager-stage.app.eng.rdu2.redhat.com/
Create activation key at https://access.stage.redhat.com/management/activation_keys
Create RHSM API token at https://access.stage.redhat.com/management/api

## idm-ci Quay container

```
$ podman login quay.io
```

```
$ make run-idm-ci
```

Log into RH Kerberos realm. mrack uses Kerberos to provision machines.

```
# kinit your-kerberos-name
```

Run test environment

```
# te --upto test idm-ci/metadata/hmsidm-dev.yaml
```

Unregister hosts from Insights and tear down VMs

```
# te --upto teardown idm-ci/metadata/hmsidm-dev.yaml
```
