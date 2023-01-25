BLACK=black

.PHONY: all
all: lint ipa-consoledot.spec

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

ipa-consoledot.spec: ipa-consoledot.spec.rpkg
	rpkg spec --outdir .