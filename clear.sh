#!/bin/bash
juju remove-application tls-client
juju remove-application cert-manager

microk8s.kubectl delete -f resources/self-signed-issuer.yaml
microk8s.kubectl delete -f ./resources/cert-manager.yaml
