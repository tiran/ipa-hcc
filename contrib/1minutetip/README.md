# Testing with 1minutetip (1MT)

## Installation of 1minutetip

Follow instructions at https://source.redhat.com/groups/public/ccs/ccs_blog/testing_rhel_in_a_fast_way_1_minute_tip

## RHC and Red Hat API keys

You need a Red Hat account on https://console.redhat.com/ with an EBS number.
If you are unable to access Insights and other services on Console, then your
account is missing EBS number, and you have to contact Red Hat support.

* Create an activation key at https://access.redhat.com/management/activation_keys
  and make note or your org id, too.
* Create a refresh token https://access.redhat.com/management/api and safe it.

## Testing ipa-hcc with 1minutetip

All commands must be run from **this** directory. 1minutetip executes the
Ansible playbook `tests/tests.yaml` with help of `standard-test-roles`
package.

```
cd contrib/1minutetip
```

1minutetip uses Kerberos authentication to provision machines. You must have
a valid Kerberos TGT (`kinit ...`).

### Install a new server

1) Run 1minutetip with larger instance + rng
   ```
   1minutetip --flavor ci.m1.medium.rng rhel-8.7
   ```
2) SSH into the machine (press `s`)
3) Connect to RHC and Insights`rhc connect -o ORGID -a KEY`
4) RHEL 7: `insights-client --register`
5) `dnf install ipa-hcc-registration-service ipa-hcc-server-plugin`
   Package installation reads the org id from the RHSM cert and updates
   IPA's global configuration.
6) Write refresh token to `/etc/ipa/hcc/refresh_token`.

### Install a client (in a separate session)

1) Get IPv4 address from server (e.g. `ip a` or output of `1minutetip`)
2) Run 1minutetip with default instance and server IP
   ```
   IPASERVER_IP=$IP 1minutetip rhel-8.7
   ```
3) SSH into the machine (press `s`)
4) Enable service `systemctl enable ipa-hcc-auto-enrollment.service`
5) `rhc connect -o ORGID -a KEY`
6) RHEL 7: `insights-client --register`
7) Watch the magic happen: `journalctl -f -u ipa-hcc-auto-enrollment.service`

## Tips

- Use `r` to restart the playbook
- Use `s` to ssh into the machine
- Update your local `/etc/hosts` and use a **private** browsing session
  to connect to IPA UI. Private sessions do not persist the private CA
  certificate of an IPA installation.
