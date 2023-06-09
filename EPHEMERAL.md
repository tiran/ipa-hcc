# Deploy in ephemeral environment

## Prepare and deploy idm-domains-backend

See `idm-domains-backend`'s `README.md` and and `DEVELOPMENT.md` how to set
up your local environment and how to deploy to ephemeral.

```
cd idm-domains-backend
```

Login and deploy backend:

```
make ephemeral-login
make ephemeral-namespace-create
make ephemeral-deploy EPHEMERAL_LOG_LEVEL=trace
```

Add `EPHEMERAL_NO_BUILD=y` if the container image is fresh.

Extend lifetime of ephemeral environment by 4 hours

```
.venv/bin/bonfire namespace extend --duration 4h $(oc project -q)
```

Get configuration

```
make ephemeral-namespace-describe
```

## Create domain stub

```
./scripts/get-ipa-hcc-register.py
```

The script creates a domain stub in the backend and prints the
`ipa-hcc register` command. It also creates `idm-ci-secrets` file, which is
later used by idm-ci.

## Create a test instance of RHEL IdM with idm-ci

```
cd ipa-hcc
```

Copy `idm-ci-secrets` from `idm-domains-backend` to local directory
`idm-ci/secrets`. The variables `RHC_KEY` and `RH_API_TOKEN` are currently
not used in ephemeral environment. The values for `HMSIDM_BACKEND`,
`EPHEMERAL_USERNAME`, and `EPHEMERAL_PASSWORD` are retrieved from
ephemeral cluster configuration with the `oc` command. Every ephemeral
environment has a different value for backend hostname and password.

Start the idm-ci container. The container image is only accessible by
privileged user accounts.

```
make run-idm-ci
```

Inside the container log into `IPA.REDHAT.COM` Kerberos realm. Your Kerberos
credentials are used to provision machines in internal IdM-Ops managed cloud.
Then source the secret file and run `te` to deploy an IPA cluster.

```
kinit $YOUR_REDHAT_LOGIN
. idm-ci/secrets
te --upto server idm-ci/metadata/hmsidm-ephemeral.yaml
```

To re-deploy code and refresh configuration:

```
te --phase pkg idm-ci/metadata/hmsidm-ephemeral.yaml
```

### Manual configuring /etc/ipa/hcc.conf

The `idm_api_url` and `dev_password` is different for each ephemeral
environment. The other values usually don't change or are ignored. The
`dev_org_id` and `dev_cert_cn` settings enable `X-Rh-Fake-Identity`
development header. The `dev_username` and `dev_password` are required to
authenticate HTTPS requests with ephemeral's ingress. Otherwise requests
won't even reach the backend.

```
[hcc]
token_url=https://sso.invalid/auth/realms/redhat-external/protocol/openid-connect/token
inventory_api_url=https://console.invalid/api/inventory/v1
# oc get routes -l app=hmsidm-backend -o jsonpath='{.items[0].spec.host}'
idm_api_url=https://HMSIDM-BACKEND/api/hmsidm/v1
dev_org_id=12345
dev_cert_cn=6f324116-b3d2-11ed-8a37-482ae3863d30
dev_username=jdoe
# oc get secrets/env-$(oc project -q)-keycloak -o jsonpath='{.data.defaultPassword}' | base64 -d
dev_password=PASSWORD
```

Then restart the D-BUs service and Apache HTTPd:

```
systemctl restart ipa-hcc-dbus.service httpd.service
```

## Register IPA domain with idm-domains-backend

Use the information from `host-info.txt` to login into the IPA server

```
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./config/id_rsa cloud-user@...
sudo -s
```

Then use the output of `./scripts/get-ipa-hcc-register.py` to register the domain:

```
ipa-hcc register ... ...
```

## Cleanup

Finally tear down the test cluster with

```
te --phase teardown idm-ci/metadata/hmsidm-ephemeral.yaml
```
