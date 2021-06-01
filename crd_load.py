#!/usr/bin/python3

from kubernetes import client, config
from kubernetes.utils import create_from_yaml

crd_file = 'static/cert-manager.crds.yaml'
config.load_kube_config('/tmp/kube.config')

with client.ApiClient() as k8s_client:
    create_from_yaml(k8s_client, crd_file, namespace='cm-charm')

