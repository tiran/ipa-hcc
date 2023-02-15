BLACK=black
CERT=tests/clients/3ecb23bf-c99b-40ec-bec5-d884a63ddf12.pem

.PHONY: all
all: test rehash lint

.PHONY: clean-idm-ci
clean-idm-ci:
	rm -rf config credentials
	rm -f mrack.* runner.log

.PHONY: clean
clean: clean-idm-ci
	rm -rf .tox
	find -name '*.pyc' -delete
	find -name __pycache__ | xargs rm -rf

.PHONY: lint
lint:
	$(BLACK) --check .
	yamllint --strict .

.PHONY: black
black:
	$(BLACK) .

.PHONY: rpkg
rpkg:
	@rm -rf .tox/rpkg
	@mkdir -p .tox/rpkg
	rpkg local --outdir $$(pwd)/.tox/rpkg
	rpmlint --ignore-unused-rpmlintrc --strict -r ipa-hcc.rpmlintrc .tox/rpkg/

.PHONY: test
test:
	openssl verify -purpose sslclient -CAfile rhsm/redhat-candlepin-bundle.pem $(CERT)
	openssl verify -purpose sslclient -CApath rhsm/cacerts/ $(CERT)

.PHONY: run-idm-ci
run-idm-ci:
	@# tmpfs at /root/.ansible is needed to work around an SELinux violation
	@# when copying files from fusefs to mount point.
	podman run -ti --rm \
		--pull always \
		-v $(PWD):/ipa-hcc:Z \
		-w /ipa-hcc \
		--tmpfs /root/.ansible:rw,mode=750 \
		quay.io/idmops/idm-ci:latest /bin/bash

.PHONY: rehash
rehash:
	openssl rehash rhsm/cacerts/
