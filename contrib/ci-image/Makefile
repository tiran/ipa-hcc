PREFIX = quay.io/tiran/ipa-hcc-ci

.PHONY: all 8 9 fedora push
all: 8 9 fedora

8:
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

9:
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

fedora:
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

push: 8 9 fedora
	podman push $(PREFIX):8
	podman push $(PREFIX):9
	podman push $(PREFIX):fedora
