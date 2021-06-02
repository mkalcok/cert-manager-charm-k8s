from jinja2 import Environment, FileSystemLoader
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from ops.charm import CharmBase, CharmEvents, RelationJoinedEvent, RelationChangedEvent, EventSource, EventBase
from ops.model import WaitingStatus, ActiveStatus, Relation, Unit
from ops.framework import Object
from pathlib import Path
import yaml

from typing import List, Optional
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
        except ApiException as exc:
            logger.error("Exception when calling CustomObjectsApi->create_namespaced_"
                         "custom_object: %s", exc)

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
        except ApiException as exc:
            if exc.status == 404:
                logger.info('Resource already gone')
            else:
                logger.error("Exception caught when deleting custom object: %s", exc)

    @classmethod
    def get(cls, k8s_client, name, namespace=None):
        api = client.CustomObjectsApi(k8s_client)
        logger.info('Fetching custom resource: %s', name)
        try:
            if namespace:
                resource = api.get_namespaced_custom_object(cls.group, cls.version,
                                                            namespace, cls.plural, name)
            else:
                resource = api.get_cluster_custom_object(cls.group, cls.version,
                                                         cls.plural, name)
        except ApiException as exc:
            logger.error("Exception when calling CustomObjectsApi->get_namespaced"
                         "custom_object: %s", exc)
        return resource


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


class CertificateReadyEvent(EventBase):

    def __init__(self, handle, name):
        super(CertificateReadyEvent, self).__init__(handle)
        self.name = name

    def snapshot(self):
        return {'name': self.name}

    def restore(self, snapshot: dict):
        self.name = snapshot['name']


class CertificatesEvents(CharmEvents):

    certificates_ready = EventSource(CertificateReadyEvent)


class CertificatesInterface(Object):

    NAME = 'certificates'

    def __init__(self, charm: CharmBase):
        super().__init__(charm, self.NAME)
        self.charm = charm

    @staticmethod
    def _unit_count_check(relation: Relation):
        unit_count = len(relation.units)
        app_name = relation.app.name
        if unit_count > 1:
            warning = (f'Unsupported number of {app_name} units: {unit_count}. '
                       f'{app_name} does not support more than 1 active unit.')
            logger.warning(warning)


class CertificatesProvides(CertificatesInterface):

    def __init__(self, charm: CharmBase):
        super().__init__(charm)

        self.framework.observe(self.charm.on.certificates_relation_changed,
                               self._on_relation_changed)
        self.framework.observe(self.charm.on.certificates_relation_joined,
                               self._on_relation_joined)

        resource_dir = Path(__file__).parent.joinpath('resources/').resolve()
        resource_loader = FileSystemLoader(searchpath=resource_dir)
        self.resource_templates = Environment(loader=resource_loader)

    def update_ca_status(self, ca_ready: bool):
        for relation in self.charm.model.relations['certificates']:
            relation.data[self.charm.unit].update({'ca_ready': str(ca_ready)})

    def _on_relation_joined(self, event: RelationJoinedEvent):
        ca_ready = self.charm.is_ca_ready()
        event.relation.data[self.charm.unit].update({'ca_ready': str(ca_ready)})

    def _on_relation_changed(self, event: RelationChangedEvent):
        if self.charm.is_ca_ready():
            needs_cert = event.relation.data[event.unit].get('needs_certificate') == 'True'
            cert_ready = event.relation.data[self.charm.unit].get('certificate_ready', '')
            if needs_cert and not cert_ready:
                common_name = event.relation.data[event.unit].get('common_name')
                self.create_certificate(common_name)
                event.relation.data[self.charm.unit].update({'certificate_ready': common_name})

    def create_certificate(self, common_name):
        config.load_incluster_config()
        logger.error('Certificate requested for %s', common_name)

        default_csr = {
            'name': common_name,
            'namespace': self.model.name,
            'org': 'juju',
            'duration': '2160h',
            'renew_before': '360h',
            'common_name': common_name,
            'key_size': '2048',
        }

        template = self.resource_templates.get_template('cert.yaml.j2')
        raw_cert_resource = template.render(**default_csr)
        certificate_resource = resources_from_yaml(raw_cert_resource)[0]
        with client.ApiClient() as k8s_client:
            certificate_resource.create(k8s_client)


class CertificatesRequires(CertificatesInterface):

    def __init__(self, charm: CharmBase):
        super(CertificatesRequires, self).__init__(charm)

        self.framework.observe(self.charm.on.certificates_relation_joined,
                               self._on_relation_joined)
        self.framework.observe(self.charm.on.certificates_relation_changed,
                               self._on_relation_changed)

    def get_cert_manager_unit(self, relation: Relation) -> Unit:
        self._unit_count_check(relation)
        return next(iter(relation.units))

    def is_ca_ready(self, ca_relation: Optional[Relation] = None) -> bool:
        result = False
        if ca_relation is None:
            ca_relation: Relation = self.charm.model.get_relation('certificates')
        if ca_relation:
            cert_manager = self.get_cert_manager_unit(ca_relation)
            result = ca_relation.data[cert_manager].get('ca_ready') == 'True'
        logger.debug('Certificate Authority is ready: %s', result)
        return result

    def _on_relation_joined(self, event: RelationJoinedEvent):
        logger.debug('Relation with Certificate Authority joined.')
        self.charm.unit.status = WaitingStatus('Waiting on TLS certificate.')
        if self.is_ca_ready(event.relation):
            self.request_certificate(event.relation)

    def _on_relation_changed(self, event: RelationChangedEvent):
        logger.debug('Relation with Certificate Authority changed.')
        ca_ready = self.is_ca_ready(event.relation)
        needs_cert = event.relation.data[self.charm.unit].get('needs_certificate', 'True')
        certificate_ready = event.relation.data[event.unit].get('certificate_ready', '')

        if ca_ready and needs_cert == 'True' and not certificate_ready:
            self.request_certificate(event.relation)

        if needs_cert and certificate_ready:
            logger.info('Certificate is ready with name: %s', certificate_ready)
            event.relation.data[self.charm.unit].update({'needs_certificate': 'False'})
            self.charm.on.certificates_ready.emit(name=certificate_ready)
            self.charm.unit.status = ActiveStatus()

    def request_certificate(self, relation: Relation, common_name: str = ''):
        if not common_name:
            common_name = self.charm.unit.name.replace('/', '.')

        logger.debug('Requesting certificate: %s', common_name)
        relation.data[self.charm.unit].update({'needs_certificate': 'True',
                                               'common_name': common_name})

    @staticmethod
    def fetch_certificate(name, namespace):
        config.load_incluster_config()
        with client.ApiClient() as k8s_client:
            return Certificate.get(k8s_client, name, namespace)
