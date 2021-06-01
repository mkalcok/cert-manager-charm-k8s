#!/usr/bin/env python3
# Copyright 2021 Martin Kalcok
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import json
import logging

from jinja2 import Environment, FileSystemLoader
from kubernetes import client, config
from kubernetes.utils import create_from_yaml
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

from charms.mkalcok_certificates.v0.certificates import (
    CertificatesProvides,
    CertificatesEvents,
    CustomResource,
    resources_from_yaml,
)

logger = logging.getLogger(__name__)
logging.getLogger('kubernetes').setLevel(logging.INFO)


class CertManagerCharm(CharmBase):
    """Charm the service."""

    CRD_FILE = 'resources/cert-manager.crds.yaml'
    custom_resources = [ 
        "certificaterequests.cert-manager.io",
        "certificates.cert-manager.io",
        "challenges.acme.cert-manager.io",
        "clusterissuers.cert-manager.io",
        "issuers.cert-manager.io",
        "orders.acme.cert-manager.io",
    ]

    _stored = StoredState()
    on = CertificatesEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        self.certificates = CertificatesProvides(self)

        self.framework.observe(self.on.certificates_requested,
                               self.certificates._on_certificate_requested)

        resource_loader = FileSystemLoader(searchpath='./resources')
        self.resource_templates = Environment(loader=resource_loader)

        self._stored.set_default(config=dict())
        for key, value in self.config.items():
            if key not in self._stored.config:
                self._stored.config[key] = value
    
    def _on_install(self, _):
        config.load_incluster_config()
        with client.ApiClient() as k8s_client:
            create_from_yaml(k8s_client, self.CRD_FILE, namespace=self.model.name)
        self.unit.status = ActiveStatus()

    def _on_stop(self, _):
        logger.error("Stopping charm")
        config.load_incluster_config()
        with client.ApiClient() as k8s_client:
            api = k8s_client.ApiextensionsV1Api()
            for resource in self.custom_resources:
                logger.info("removing %s", resource)
                api.delete_custom_resource_definition(resource)

    def _on_config_changed(self, event):
        logger.info("Changing config")
        logger.info('config: %s', self.config)
        logger.info('config cache: %s', self._stored.config)

        self_sign_enabled = self.config.get('self-signed-issuer-enabled')
        if self._stored.config['self-signed-issuer-enabled'] != self_sign_enabled:
            logger.info("self-signed-issuer-enabled changed")
            self._stored.config['self-signed-issuer-enabled'] = self_sign_enabled
            self.configure_self_signed(self_sign_enabled)

        custom_ca = self.config.get('custom-ca')
        if self._stored.config['custom-ca'] != custom_ca:
            logger.info("custom ca changed")
            self._stored.config['custom-ca'] = custom_ca
            self.configure_custom_ca(custom_ca)

        if not self.is_ca_ready():
            self.unit.status = BlockedStatus("CA not configured.")
        else:
            self.unit.status = ActiveStatus()

    def is_ca_ready(self) -> bool:
        custom_ca = bool(json.loads(self.config.get('custom-ca').replace("'", '"')))
        self_sign_ca = self.config.get('self-signed-issuer-enabled')
        return custom_ca or self_sign_ca

    def configure_self_signed(self, enabled: bool) -> None:
        config.load_incluster_config()
        template = self.resource_templates.get_template('self-signed-issuer.yaml.j2')
        custom_issuer_conf = template.render(namespace=self.model.name)
        custom_resources = resources_from_yaml(custom_issuer_conf)
        with client.ApiClient() as k8s_client:
            for resource in custom_resources:
                if enabled:
                    resource.create(k8s_client)
                else:
                    resource.delete(k8s_client)

    def configure_custom_ca(self, raw_ca_config: str) -> None:
        try:
            # juju gives us config string always single-quoted so we need to do
            # ugly replace but that shouldn't be a problem.
            ca_config = json.loads(raw_ca_config.replace("'", '"'))
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse 'custom-ca' config option: %s", exc)
            self.unit.status = BlockedStatus("Bad format of 'custom-ca' config option.")
            return

        ca_template = self.resource_templates.get_template('ca_issuer.yaml.j2')
        ca_issuer_conf = ca_template.render(namespace=self.model.name)
        ca_issuer_resources = resources_from_yaml(ca_issuer_conf)[0]

        if ca_config:
            self.create_custom_ca(ca_config, ca_issuer_resources)
        else:
            self.delete_custom_ca(ca_issuer_resources)

    def delete_custom_ca(self, issuer:CustomResource):
        config.load_incluster_config()
        with client.ApiClient() as k8s_client:
            api = client.CoreV1Api(k8s_client)
            api.delete_namespaced_secret(name='ca-key-pair', namespace=self.model.name)
            issuer.delete(k8s_client)

    def create_custom_ca(self, ca_config: dict, issuer: CustomResource) -> None:
        expected_data = {'crt', 'key'}
        if ca_config.keys() != expected_data:
            logger.error("Config option 'custom-ca' does not match expected format. "
                         "Expected keys: %s. Found keys: %s", expected_data,
                         ca_config.keys())
            self.unit.status = BlockedStatus("Bad format of 'custom-ca' config option.")
            return

        config.load_incluster_config()
        with client.ApiClient() as k8s_client:
            api = client.CoreV1Api(k8s_client)
            secret_data = {'tls.crt': ca_config['crt'], 'tls.key': ca_config['key']}
            body = client.V1Secret(api_version='v1',
                                   data=secret_data,
                                   kind='Secret',
                                   metadata={'name': 'ca-key-pair'},
                                   type='kubernetes.io/tls')
            api.create_namespaced_secret(self.model.name, body)
            issuer.create(k8s_client)

            
if __name__ == "__main__":
    main(CertManagerCharm)
