BLACK=black
CERT=tests/clients/3ecb23bf-c99b-40ec-bec5-d884a63ddf12.pem

.PHONY: all
all: test rehash lint

.PHONY: clean
clean:
	rm -rf .tox
	find -name '*.pyc' -delete
	find -name __pycache__ | xargs rm -r

.PHONY: lint
lint:
	$(BLACK) --check .

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

.PHONY: rehash
rehash:
	openssl rehash rhsm/cacerts/
