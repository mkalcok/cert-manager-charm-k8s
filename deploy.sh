#!/bin/bash
charmcraft pack
juju deploy ./cert-manager.charm --resource controller-image=quay.io/jetstack/cert-manager-controller:v1.3.1 --resource webhook-image=quay.io/jetstack/cert-manager-webhook:v1.3.1 --resource cainjector-image=quay.io/jetstack/cert-manager-cainjector:v1.3.1
