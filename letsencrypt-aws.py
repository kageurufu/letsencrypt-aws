import datetime
import json
import os
import sys
import time

import OpenSSL.crypto
import acme.challenges
import acme.client
import acme.jose
import boto3
import click
import rfc3986
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

DEFAULT_ACME_DIRECTORY_URL = "https://acme-v01.api.letsencrypt.org/directory"
CERTIFICATE_EXPIRATION_THRESHOLD = datetime.timedelta(days=45)
# One day
PERSISTENT_SLEEP_INTERVAL = 60 * 60 * 24
DNS_TTL = 30


class Logger(object):
    def __init__(self):
        self._out = sys.stdout

    def emit(self, event, **data):
        formatted_data = " ".join(
            "{}={!r}".format(k, v) for k, v in data.iteritems()
        )
        self._out.write("{} [{}] {}\n".format(
            datetime.datetime.utcnow().replace(microsecond=0),
            event,
            formatted_data
        ))


class CertificateRequest(object):
    def __init__(self, cert_location, dns_challenge_completer, hosts,
                 key_type):
        self.cert_location = cert_location
        self.dns_challenge_completer = dns_challenge_completer

        self.hosts = hosts
        self.key_type = key_type


class AWSCertificate(object):
    def __init__(self, iam_client, client, name, port=443):
        self.iam_client = iam_client
        self.client = client
        self.name = name
        self.port = port

    def upload_certificate(self, logger, hosts, private_key, pem_certificate,
                           pem_certificate_chain):
        logger.emit("updating.upload-iam-certificate", name=self.name)

        response = self.iam_client.upload_server_certificate(
            ServerCertificateName=generate_certificate_name(
                hosts,
                x509.load_pem_x509_certificate(
                    pem_certificate, default_backend()
                )
            ),
            PrivateKey=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            CertificateBody=pem_certificate,
            CertificateChain=pem_certificate_chain,
        )

        new_cert_arn = response["ServerCertificateMetadata"]["Arn"]
        return new_cert_arn

    def get_certificate(self, certificate_id):
        paginator = self.iam_client.get_paginator("list_server_certificates")
        for page in paginator.paginate():
            for server_certificate in page["ServerCertificateMetadataList"]:
                if server_certificate["Arn"] == certificate_id:
                    cert_name = server_certificate["ServerCertificateName"]
                    response = self.iam_client.get_server_certificate(
                        ServerCertificateName=cert_name,
                    )
                    return x509.load_pem_x509_certificate(
                        response["ServerCertificate"]["CertificateBody"],
                        default_backend(),
                    )

    def update_certificate(self, logger, new_cert_arn):
        raise NotImplementedError

    def get_current_certificate(self):
        raise NotImplementedError


class ELBCertificate(AWSCertificate):
    def get_current_certificate(self):
        response = self.client.describe_load_balancers(
            LoadBalancerNames=[self.name]
        )
        [description] = response["LoadBalancerDescriptions"]
        [certificate_id] = [
            listener["Listener"]["SSLCertificateId"]
            for listener in description["ListenerDescriptions"]
            if listener["Listener"]["LoadBalancerPort"] == self.port
            ]

        return self.get_certificate(certificate_id)

    def update_certificate(self, logger, new_cert_arn):
        logger.emit("updating-elb.set-elb-certificate", name=self.name)

        self.client.set_load_balancer_listener_ssl_certificate(
            LoadBalancerName=self.name,
            SSLCertificateId=new_cert_arn,
            LoadBalancerPort=self.port,
        )


class CloudfrontCertificate(AWSCertificate):
    def get_certificate(self, certificate_id):
        response = self.client.get_distribution_config(Id=self.name)
        cert = response["DistributionConfig"]["ViewerCertificate"]

        assert cert.get("IAMCertificateId")
        return self.get_certificate(cert['IAMCertificateId'])

    def update_certificate(self, logger, new_cert_arn):
        logger.emit(
            "updating-cloudfront.set-cloudfront-certificate",
            id=self.name
        )

        config = self.client.get_distribution_config(Id=self.name)

        cert = config["DistributionConfig"]["ViewerCertificate"]
        cert["IAMCertificateId"] = new_cert_arn

        self.client.update_distribution(DistributionConfig=config)


class ElasticBeanstalkCertificate(AWSCertificate):
    def __init__(self, iam_client, client, environment, name, port=443):
        AWSCertificate.__init__(self, iam_client, client, name, port)
        self.environment = environment

    @property
    def namespace(self):
        return "aws:elb:listener:{}".format(self.port)

    def get_current_certificate(self):
        response = self.client.describe_configuration_settings(
            ApplicationName=self.name, EnvironmentName=self.environment
        )

        certificate_id = next((
            option_setting["Value"]
            for environment in response["ConfigurationSettings"]
            for option_setting in environment["OptionSettings"]
            if option_setting["Namespace"] == self.namespace
            if option_setting["OptionName"] == "SSLCertificateId"
        ), None)

        if certificate_id:
            return self.get_certificate(certificate_id)

    def update_certificate(self, logger, new_cert_arn):
        logger.emit(
            "updating-beanstalk.set-beanstalk-certificate",
            app_name=self.name, env_name=self.environment
        )

        # Update both possible namespaces for ensured compatibility
        self.client.update_environment(
            ApplicationName=self.name,
            EnvironmentName=self.environment,
            OptionSettings=[
                {
                    "Namespace": self.namespace,
                    "OptionName": "SSLCertificateId",
                    "Value": new_cert_arn
                },
                {
                    "Namespace": 'aws:elb:loadbalancer',
                    "OptionName": "SSLCertificateId",
                    "Value": new_cert_arn
                },
            ]
        )


class Route53ChallengeCompleter(object):
    def __init__(self, route53_client):
        self.route53_client = route53_client

    def _find_zone_id_for_domain(self, domain):
        paginator = self.route53_client.get_paginator("list_hosted_zones")
        zones = []
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if (
                    domain.endswith(zone["Name"]) or
                    (domain + ".").endswith(zone["Name"])
                ) and not zone["Config"]["PrivateZone"]:
                    zones.append((zone["Name"], zone["Id"]))

        if not zones:
            raise ValueError(
                "Unable to find a Route53 hosted zone for {}".format(domain)
            )

        # Order the zones that are suffixes for our desired to domain by
        # length, this puts them in an order like:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        # And then we choose the last one, which will be the most specific.
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _change_txt_record(self, action, zone_id, domain, value):
        response = self.route53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "TXT",
                            "TTL": DNS_TTL,
                            "ResourceRecords": [
                                # For some reason TXT records need to be
                                # manually quoted.
                                {"Value": '"{}"'.format(value)}
                            ],
                        }
                    }
                ]
            }
        )
        return response["ChangeInfo"]["Id"]

    def create_txt_record(self, host, value):
        zone_id = self._find_zone_id_for_domain(host)
        change_id = self._change_txt_record(
            "CREATE",
            zone_id,
            host,
            value,
        )
        return (zone_id, change_id)

    def delete_txt_record(self, change_id, host, value):
        zone_id, _ = change_id
        self._change_txt_record(
            "DELETE",
            zone_id,
            host,
            value
        )

    def wait_for_change(self, change_id):
        _, change_id = change_id

        while True:
            response = self.route53_client.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)


def generate_rsa_private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def generate_ecdsa_private_key():
    return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())


def generate_csr(private_key, hosts):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        # This is the same thing the official letsencrypt client does.
        x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, hosts[0]),
        ])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(host)
            for host in hosts
        ]),
        # TODO: change to `critical=True` when Let's Encrypt supports it.
        critical=False,
    )
    return csr_builder.sign(private_key, hashes.SHA256(), default_backend())


def find_dns_challenge(authz):
    for combo in authz.body.resolved_combinations:
        if (
            len(combo) == 1 and
            isinstance(combo[0].chall, acme.challenges.DNS01)
        ):
            yield combo[0]


def generate_certificate_name(hosts, cert):
    return "{serial}-{expiration}-{hosts}".format(
        serial=cert.serial,
        expiration=cert.not_valid_after.date(),
        hosts="-".join(h.replace(".", "_") for h in hosts),
    )[:128]


class AuthorizationRecord(object):
    def __init__(self, host, authz, dns_challenge, change_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.change_id = change_id


def start_dns_challenge(logger, acme_client, dns_challenge_completer,
                        name, host):
    logger.emit("updating.request-acme-challenge", name=name, host=host)
    authz = acme_client.request_domain_challenges(
        host, acme_client.directory.new_authz
    )

    [dns_challenge] = find_dns_challenge(authz)

    logger.emit(
        "updating.create-txt-record", name=name, host=host
    )
    change_id = dns_challenge_completer.create_txt_record(
        dns_challenge.validation_domain_name(host),
        dns_challenge.validation(acme_client.key),

    )
    return AuthorizationRecord(
        host,
        authz,
        dns_challenge,
        change_id,
    )


def complete_dns_challenge(logger, acme_client, dns_challenge_completer,
                           name, authz_record):
    logger.emit(
        "updating.wait-for-route53",
        name=name, host=authz_record.host
    )
    dns_challenge_completer.wait_for_change(authz_record.change_id)

    response = authz_record.dns_challenge.response(acme_client.key)

    logger.emit(
        "updating.local-validation",
        name=name, host=authz_record.host
    )
    verified = response.simple_verify(
        authz_record.dns_challenge.chall,
        authz_record.host,
        acme_client.key.public_key()
    )
    if not verified:
        raise ValueError("Failed verification")

    logger.emit(
        "updating.answer-challenge",
        name=name, host=authz_record.host
    )
    acme_client.answer_challenge(authz_record.dns_challenge, response)


def request_certificate(logger, acme_client, name, authorizations, csr):
    logger.emit("updating.request-cert", name=name)
    cert_response, _ = acme_client.poll_and_request_issuance(
        acme.jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1,
                csr.public_bytes(serialization.Encoding.DER),
            )
        ),
        authzrs=[authz_record.authz for authz_record in authorizations],
    )
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    )
    pem_certificate_chain = "\n".join(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for cert in acme_client.fetch_chain(cert_response)
    )
    return pem_certificate, pem_certificate_chain


def update_aws(logger, acme_client, force_issue, cert_request, cert_only):
    logger.emit("updating", name=cert_request.cert_location.name)

    current_cert = cert_request.cert_location.get_current_certificate()
    logger.emit(
        "updating.certificate-expiration",
        name=cert_request.cert_location.name,
        expiration_date=current_cert.not_valid_after
    )
    days_until_expiration = (
        current_cert.not_valid_after - datetime.datetime.today()
    )

    try:
        san_extension = current_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        # Handle the case where an old certificate doesn't have a SAN extension
        # and always reissue in that case.
        current_domains = []
    else:
        current_domains = san_extension.value.get_values_for_type(x509.DNSName)

    if (
        days_until_expiration > CERTIFICATE_EXPIRATION_THRESHOLD and
        # If the set of hosts we want for our certificate changes, we update
        # even if the current certificate isn't expired.
        sorted(current_domains) == sorted(cert_request.hosts) and
        not force_issue
    ):
        return

    if cert_request.key_type == "rsa":
        private_key = generate_rsa_private_key()
    elif cert_request.key_type == "ecdsa":
        private_key = generate_ecdsa_private_key()
    else:
        raise ValueError(
            "Invalid key_type: {!r}".format(cert_request.key_type)
        )
    csr = generate_csr(private_key, cert_request.hosts)

    authorizations = []
    try:
        for host in cert_request.hosts:
            authz_record = start_dns_challenge(
                logger, acme_client, cert_request.dns_challenge_completer,
                cert_request.cert_location.name, host,
            )
            authorizations.append(authz_record)

        for authz_record in authorizations:
            complete_dns_challenge(
                logger, acme_client, cert_request.dns_challenge_completer,
                cert_request.cert_location.name, authz_record
            )

        pem_certificate, pem_certificate_chain = request_certificate(
            logger, acme_client, cert_request.cert_location.name,
            authorizations, csr
        )

        new_cert_arn = cert_request.cert_location.upload_certificate(
            logger, cert_request.hosts,
            private_key, pem_certificate, pem_certificate_chain
        )

        if not cert_only:
            # Sleep before trying to set the certificate, it appears to
            # sometimes fail without this.
            time.sleep(15)

            cert_request.cert_location.update_certificate(
                logger, new_cert_arn
            )
    finally:
        for authz_record in authorizations:
            logger.emit(
                "updating.delete-txt-record",
                name=cert_request.cert_location.name,
                host=authz_record.host
            )
            dns_challenge = authz_record.dns_challenge
            cert_request.dns_challenge_completer.delete_txt_record(
                authz_record.change_id,
                dns_challenge.validation_domain_name(authz_record.host),
                dns_challenge.validation(acme_client.key),
            )


def update_certs(logger, acme_client, force_issue, cert_only,
                 certificate_requests):
    for cert_request in certificate_requests:
        update_aws(
            logger,
            acme_client,
            force_issue,
            cert_request,
            cert_only,
        )


def setup_acme_client(s3_client, acme_directory_url, acme_account_key):
    uri = rfc3986.urlparse(acme_account_key)
    if uri.scheme == "file":
        if uri.host is None:
            path = uri.path
        elif uri.path is None:
            path = uri.host
        else:
            path = os.path.join(uri.host, uri.path)
        with open(path) as f:
            key = f.read()
    elif uri.scheme == "s3":
        # uri.path includes a leading "/"
        response = s3_client.get_object(Bucket=uri.host, Key=uri.path[1:])
        key = response["Body"].read()
    else:
        raise ValueError(
            "Invalid acme account key: {!r}".format(acme_account_key)
        )

    key = serialization.load_pem_private_key(
        key, password=None, backend=default_backend()
    )
    return acme_client_for_private_key(acme_directory_url, key)


def acme_client_for_private_key(acme_directory_url, private_key):
    return acme.client.Client(
        # TODO: support EC keys, when acme.jose does.
        acme_directory_url, key=acme.jose.JWKRSA(key=private_key)
    )


@click.group()
def cli():
    pass


@cli.command(name="update-certificates")
@click.option(
    "--persistent", is_flag=True, help="Runs in a loop, instead of just once."
)
@click.option(
    "--force-issue", is_flag=True, help=(
        "Issue a new certificate, even if the old one isn't close to "
        "expiration."
    )
)
@click.option(
    '--cert-only', is_flag=True, help=(
        "Only issue and upload a new certificate to IAM, without configuring "
        "a listener."
    )
)
def update_certificates(persistent=False, force_issue=False):
    logger = Logger()
    logger.emit("startup")

    if persistent and force_issue:
        raise ValueError("Can't specify both --persistent and --force-issue")

    session = boto3.Session()
    s3_client = session.client("s3")
    elb_client = session.client("elb")
    elasticbeanstalk_client = session.client("elasticbeanstalk")
    cloudfront_client = session.client("cloudfront")
    route53_client = session.client("route53")
    iam_client = session.client("iam")

    config = json.loads(os.environ["LETSENCRYPT_AWS_CONFIG"])
    domains = config["domains"]
    acme_directory_url = config.get(
        "acme_directory_url", DEFAULT_ACME_DIRECTORY_URL
    )
    acme_account_key = config["acme_account_key"]
    acme_client = setup_acme_client(
        s3_client, acme_directory_url, acme_account_key
    )

    certificate_requests = []
    for domain in domains:
        if "elb" in domain:
            cert_location = ELBCertificate(
                iam_client, elb_client,
                domain["elb"]["name"], int(domain["elb"].get("port", 443))
            )
        elif 'elasticbeanstalk' in domain:
            cert_location = ElasticBeanstalkCertificate(
                iam_client, elasticbeanstalk_client,
                domain["elasticbeanstalk"]["environment"],
                domain["elasticbeanstalk"]["name"]
            )
        elif 'cloudfront' in domain:
            cert_location = CloudfrontCertificate(
                iam_client, cloudfront_client,
                domain["cloudfront"]["id"]
            )
        else:
            raise ValueError(
                "Unknown certificate location: {!r}".format(domain)
            )

        certificate_requests.append(CertificateRequest(
            cert_location,
            Route53ChallengeCompleter(route53_client),
            domain["hosts"],
            domain.get("key_type", "rsa"),
        ))

    if persistent:
        logger.emit("running", mode="persistent")
        while True:
            update_certs(
                logger, acme_client,
                force_issue, certificate_requests
            )
            # Sleep before we check again
            logger.emit("sleeping", duration=PERSISTENT_SLEEP_INTERVAL)
            time.sleep(PERSISTENT_SLEEP_INTERVAL)
    else:
        logger.emit("running", mode="single")
        update_certs(
            logger, acme_client,
            force_issue, certificate_requests
        )


@cli.command()
@click.argument("email")
@click.option(
    "--out",
    type=click.File("w"),
    default="-",
    help="Where to write the private key to. Defaults to stdout."
)
def register(email, out):
    logger = Logger()
    config = json.loads(os.environ.get("LETSENCRYPT_AWS_CONFIG", "{}"))
    acme_directory_url = config.get(
        "acme_directory_url", DEFAULT_ACME_DIRECTORY_URL
    )

    logger.emit("acme-register.generate-key")
    private_key = generate_rsa_private_key()
    acme_client = acme_client_for_private_key(acme_directory_url, private_key)

    logger.emit("acme-register.register", email=email)
    registration = acme_client.register(
        acme.messages.NewRegistration.from_data(email=email)
    )
    logger.emit("acme-register.agree-to-tos")
    acme_client.agree_to_tos(registration)
    out.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))


if __name__ == "__main__":
    cli()
