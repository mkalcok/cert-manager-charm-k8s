# cert-manager

## Description

cert-manager is, as name suggests, a kubernetes application that acts as a
certificate authority and provides a API which other k8s applications can use to
create and renew certificates. cert-manager can be configured to sign
certificates with:
* self-signed CA certificate
* explicitly configured CA certificate
* CA certificate issued  by ACME service (like letsencrypt)

## Usage

this charm is not yet ready for usage.

## TODO

* Finish the installation process. Currently the application is not 100%
functional after charm deployment.
* Enrich the interface for creation of certificates, currently it only
takes the `common_name` as parameter when creating new certificate.


## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Testing

The Python operator framework includes a very nice harness for testing
operator behaviour without full deployment. Just `run_tests`:

    ./run_tests
