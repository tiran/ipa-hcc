PREFIX = quay.io/tiran/ipa-hcc-ci

.PHONY: all 7 8 9 fedora
all: 7 8 9 fedora

7:
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

8:
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

9:
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

fedora:
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .
