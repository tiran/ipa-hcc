BLACK=black
CERT=tests/clients/3ecb23bf-c99b-40ec-bec5-d884a63ddf12.pem

.PHONY: all
all: test rehash lint

.PHONY: clean
clean:
	rm -rf .rpkg .tox

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
	rpmlint --strict -r ipa-consoledot.rpmlintrc .tox/rpkg/

.PHONY: test
test:
	openssl verify -purpose sslclient -CAfile rhsm/redhat-candlepin-bundle.pem $(CERT)
	openssl verify -purpose sslclient -CApath rhsm/cacerts/ $(CERT)

.PHONY: rehash
rehash:
	openssl rehash rhsm/cacerts/