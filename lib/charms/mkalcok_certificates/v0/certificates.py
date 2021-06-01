from jinja2 import Environment, FileSystemLoader
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from ops.charm import CharmBase, CharmEvents, RelationJoinedEvent, RelationEvent, EventSource, EventBase
from ops.framework import Object
from pathlib import Path
import yaml

from typing import List
import logging

logger = logging.getLogger(__name__)
logging.getLogger('kubernetes').setLevel(logging.INFO)


class CustomResource:
    group = ''
    version = ''
    name = ''
    plural = ''

    def __init__(self, data, name, namespace=''):
        self.namespace = namespace
        self.data = data
        self.name = name

    def create(self, k8s_client):
        api = client.CustomObjectsApi(k8s_client)
        logger.info("Creating custom resource: %s", self.name)
        try:
            if self.namespace:
                api.create_namespaced_custom_object(self.group, self.version,
                                                    self.namespace, self.plural,
                                                    self.data)
            else:
                api.create_cluster_custom_object(self.group, self.version, self.plural,
                                                 self.data)
        except ApiException as e:
            logger.error("Exception when calling CustomObjectsApi->create_namespaced_"
                         "custom_object: %s", e)

    def delete(self, k8s_client):
        api = client.CustomObjectsApi(k8s_client)
        logger.info("Attempting to delete custom resource: %s", self.name)
        try:
            if self.namespace:
               api.delete_namespaced_custom_object(self.group, self.version,
                                                    self.namespace, self.plural,
                                                    self.name)
            else:
                api.delete_cluster_custom_object(self.group, self.version, self.plural,
                                                 self.name)
        except ApiException as e:
            if e.status == 404:
                logger.info('Resource already gone')
            else:
                logger.error("Exception caught when deleting custom object: %s", e)


class Issuer(CustomResource):
    group = 'cert-manager.io'
    version = 'v1'
    plural = 'issuers'


class ClusterIssuer(CustomResource):
    group = 'cert-manager.io'
    version = 'v1'
    plural = 'clusterissuers'


class Certificate(CustomResource):
    group = 'cert-manager.io'
    version = 'v1'
    plural = 'certificates'


resource_map = {
    'Issuer': Issuer,
    'ClusterIssuer': ClusterIssuer,
    'Certificate': Certificate,
}


def resources_from_yaml(raw_crds:str) -> List['CustomResource']:
    resources = []
    for resource in yaml.safe_load_all(raw_crds):
        kind = resource.get('kind')
        metadata = resource.get('metadata', {})
        namespace = metadata.get('namespace', '')
        name = metadata.get('name')
        resource_obj = resource_map.get(kind)
        if resource:
            logger.debug('Loading resource: %s', resource)
            resources.append(resource_obj(data=resource, name=name,
                                          namespace=namespace))
    return resources


class CertificateRequestedEvent(EventBase):

    def __init__(self, handle):
        super(CertificateRequestedEvent, self).__init__(handle)
        self.common_name = 'hello.world'

    def snapshot(self):
        return {'common_name': self.common_name}

    def restore(self, snapshot: dict):
        self.common_name = snapshot['common_name']


class CertificatesEvents(CharmEvents):

    certificates_requested = EventSource(CertificateRequestedEvent)


class CertificatesInterface(Object):

    NAME = 'certificates'

    def __init__(self, charm: CharmBase):
        super().__init__(charm, self.NAME)
        self.charm = charm


class CertificatesProvides(CertificatesInterface):

    def __init__(self, charm: CharmBase):
        super().__init__(charm)

        # self.charm.framework.observe(
        #     charm.on.certificates_requested, self._on_certificate_requested)

        logger.debug('observed events: %s', charm.on)

        resource_dir = Path(__file__).parent.joinpath('resources/').resolve()
        resource_loader = FileSystemLoader(searchpath=resource_dir)
        self.resource_templates = Environment(loader=resource_loader)

    def _on_certificate_requested(self, event: CertificateRequestedEvent):
        config.load_incluster_config()
        logger.error('Certificates joined')
        logger.error(event)
        logger.error(event.common_name)

        default_csr = {
            'name': 'test.juju.unit',
            'namespace': self.model.name,
            'org': 'juju',
            'duration': '2160h',
            'renew_before': '360h',
            'common_name': 'test.juju.unit',
            'key_size': '2048',
        }

        template = self.resource_templates.get_template('cert.yaml.j2')
        raw_cert_resource = template.render(**default_csr)
        certificate_resource = resources_from_yaml(raw_cert_resource)[0]
        with client.ApiClient() as k8s_client:
            certificate_resource.create(k8s_client)


class CertificatesRequires(CertificatesInterface):

    def request_certificate(self, common_name):
        # ca_relation = self.charm.model.get_relation('certificates')
        # logger.info('Relation %s', ca_relation)
        # logger.info('Event %s', event)
        # logger.info('Units %s', ca_relation.units)
        # logger.info(dir(event))
        # cert_manager_unit = next(iter(ca_relation.units))
        self.charm.on.certificates_requested.emit()
