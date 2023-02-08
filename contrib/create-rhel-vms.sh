#!/bin/sh
set -ex

# https://access.redhat.com/management/activation_keys
ORGID=12345
ACTIVATIONKEY=mysecretkey
# RHEL version
VER=8.7
# configuration
DOMAIN="mydomain.example"
PASSWORD=Secret123

# Download "KVM Guest Image" qcow2 file from
# https://access.redhat.com/downloads/content/479/ver=/rhel---8/8.7/x86_64/product-software
BASE_IMG=rhel-${VER}-x86_64-kvm.qcow2
# copy-on-write clones
IMG=rhel-img-${VER}-base.qcow2
IMG_SERVER=rhel-img-${VER}-ipaserver.qcow2
IMG_CLIENT=rhel-img-${VER}-ipaclient1.qcow2


if [ ! -f $IMG ]; then
    rm -f $IMG_CLIENT $IMG_SERVER

    qemu-img create -f qcow2 -F qcow2 -b $BASE_IMG $IMG

    virt-customize \
        --format qcow2 \
        --timezone Europe/Berlin \
        --run-command "id $USER || useradd -m -u $UID -U -s /bin/bash -G wheel $USER" \
        --password "$USER:password:$PASSWORD" \
        --run-command "rm -rf /home/$USER/.ssh" \
        --ssh-inject "$USER" \
        --ssh-inject "root" \
        --write "/etc/sudoers.d/passwordless:%wheel  ALL = (ALL) NOPASSWD: ALL" \
        --run-command "subscription-manager register --org=$ORGID --activationkey=$ACTIVATIONKEY" \
        --run-command 'dnf -y module enable idm:DL1' \
        --update \
        --install 'openssh-server,openssl,vim-enhanced,git,rsync,ipa-server,rhc,insights-client,dnf-command(copr)' \
        --run-command 'dnf copr enable copr.devel.redhat.com/cheimes/ipa-hcc' \
        --sm-unregister \
        -a $IMG

    virt-sysprep \
        --operations defaults,-ssh-userdir \
        --selinux-relabel \
        -a $IMG
fi

if [ ! -f $IMG_SERVER ]; then
    qemu-img create -f qcow2 -F qcow2 -b $IMG $IMG_SERVER

    virt-customize \
        --hostname ipaserver.$DOMAIN \
        --selinux-relabel \
        -a $IMG_SERVER
fi

if [ ! -f $IMG_CLIENT ]; then
    qemu-img create -f qcow2 -F qcow2 -b $IMG $IMG_CLIENT

    virt-customize \
        --hostname ipaclient1.$DOMAIN \
        --selinux-relabel \
        -a $IMG_CLIENT
fi
