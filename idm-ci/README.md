# Continuous Integration with idm-ci

## Supported OS

- rhel-8.7
- rhel-8.8 (dev)
- rhel-9.1
- rhel-9.2 (dev)

(*) Kerberos KDC on RHEL 8.6 server uses SHA-1 for PKINIT, which is
incompatible with RHEL 9's crypto policy.

## Configuration

All playbooks load configuration from `idm-ci/config/hmsidm-config.yaml`,
which loads the settings from environment variables. The internal
CI/CD pipeline provides secrets. For local testing you can copy the file
`idm-ci/secrets.example` to `idm-ci/secrets`, fill it, and source it.

### Production

- Create activation key at https://access.redhat.com/management/activation_keys
- Create RHSM API token at https://access.redhat.com/management/api

See https://access.redhat.com/articles/3626371

If your account cannot access Insights, then it might miss the EBS
number. Contact RH customer support to add an EBS number to an account.

### Stage

- Create account on Ethel stage account manager. The internal CI/CD variable
  `ETHEL_EXPORTED_ACOUNTS` contains a CSV export with necessary lists
  entitlements.
- Create activation key at https://access.stage.redhat.com/management/activation_keys
- Create RHSM API token at https://access.stage.redhat.com/management/api

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

Source settings and secrets (use `idm-ci/secrets.example` as template)

```
# . idm-ci/secrets
```

Run test environment

```
# te --upto test idm-ci/metadata/hmsidm-dev.yaml
```

The file `host-info.txt` in the project's root directory contains a list
of IP addresses and SSH commands to log into the hosts.

Unregister hosts from Insights and tear down VMs

```
# te --phase teardown idm-ci/metadata/hmsidm-dev.yaml
```
