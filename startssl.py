#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
A python/CLI API for some StartCom StartSSL functions.

Website: https://github.com/freddy36/StartSSL_API

Dependencies:
  apt-get install python-httplib2 python-pyasn1 python3-pyasn1-modules

Copyright (c) 2014, Frederik Kriewitz <frederik@kriewitz.eu>.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301 USA
"""

from __future__ import print_function
try:
    from urllib.parse import urlencode  # python 3
except ImportError:
    from urllib import urlencode  # python 2

__version__ = "1.00"

import argparse
import httplib2
import re
import datetime
import os
import sys
import traceback

import base64
import pyasn1
import pyasn1.codec.der.decoder
import pyasn1_modules.rfc2314
import pyasn1_modules.rfc2459


class CSR:
    """
    Parses CSRs
    """
    id_PKCS9_extensionRequest = pyasn1.type.univ.ObjectIdentifier('1.2.840.113549.1.9.14')

    def __init__(self, pem_csr):
        if 'read' in dir(pem_csr):
            pem_csr = pem_csr.read()

        self.pem = pem_csr
        self.__parse_pem()

    def __parse_pem(self):
        """
        Parses a PEM encoded CSR to asn1
        """
        matches = re.search(
            "-----BEGIN CERTIFICATE REQUEST-----([A-Za-z0-9+/=\n\r\t ]*)-----END CERTIFICATE REQUEST-----", self.pem)
        if not matches:
            raise ValueError("Not a valid PEM CSR")

        csr_b64 = matches.group(1)
        csr_bin = base64.b64decode(csr_b64)
        self.asn1, _ = pyasn1.codec.der.decoder.decode(csr_bin, asn1Spec=pyasn1_modules.rfc2314.CertificationRequest())

    def get_pem(self):
        """
        Returns the PEM encoded CSR.
        """
        return self.pem

    def get_common_name(self):
        """
        Returns the common-name
        """
        subject_rdn_sequence = self.asn1.getComponentByName('certificationRequestInfo').getComponentByName('subject')[0]
        for subject in subject_rdn_sequence:
            name = subject[0]
            oid = name.getComponentByName('type')
            value = name.getComponentByName('value')
            if oid == pyasn1_modules.rfc2459.id_at_commonName:
                value = pyasn1.codec.der.decoder.decode(value, asn1Spec=pyasn1_modules.rfc2459.DirectoryString())[0]
                return str(value.getComponent())

    def get_subject_alt_names(self, types=None):
        """
        Yields (type, value) tupels for each SubjectAltName.
        Types can be specified to filter limit the result to specific types.
        """
        for attribute_type, attribute_value in self.asn1.getComponentByName(
                'certificationRequestInfo').getComponentByName('attributes'):
            if attribute_type != self.id_PKCS9_extensionRequest:  # we're only interested in the extension request part
                continue

            extensions, _ = pyasn1.codec.der.decoder.decode(attribute_value[0],
                                                            asn1Spec=pyasn1_modules.rfc2459.Extensions())
            for extension in extensions:
                oid = extension.getComponentByName('extnID')
                if oid != pyasn1_modules.rfc2459.id_ce_subjectAltName:  # we're only interested in the subject alternative name
                    continue

                subject_alt_names_raw = pyasn1.codec.der.decoder.decode(extension.getComponentByName('extnValue'),
                                                                        asn1Spec=pyasn1.type.univ.OctetString())[0]
                subject_alt_names = pyasn1.codec.der.decoder.decode(subject_alt_names_raw,
                                                                    asn1Spec=pyasn1_modules.rfc2459.SubjectAltName())[0]
                for general_name in subject_alt_names:
                    subject_alt_name_type = general_name.getName()
                    subject_alt_name_value = general_name.getComponent()
                    if types and subject_alt_name_type not in types:  # skip unwanted types
                        continue
                    yield subject_alt_name_type, str(subject_alt_name_value)


class API(object):
    """
    Provides a python API for some StartCOM StartSSL functions
    """
    STARTCOM_CA = "/etc/ssl/certs/StartCom_Certification_Authority.pem"
    STARTSSL_BASEURI = "https://www.startssl.com"
    STARTSSL_AUTHURI = "https://auth.startssl.com"

    # key: value of select field (new certificate request)
    # value: descriptions in the certificate list
    CERTIFICATE_PROFILES = {'smime': "S/MIME", 'server': "Server", 'xmpp': "XMPP", 'code': "Object"}

    RETRIEVE_CERTIFICATE_LIST = re.compile(
        '<option value=\\\\"(?P<id>\d+)\\\\" style=\\\\"background-color: #(?P<color>[0-9A-F]{6});\\\\">(?P<name>[^-]+?) \((?P<profile_description>[\w/]+?) - (?P<class>[\w\d ]+?) - (?P<expires_year>\d{4})-(?P<expires_month>\d{2})-(?P<expires_day>\d{2})\)</option>',
        re.UNICODE)
    RETRIEVE_CERTIFICATE_CERT = re.compile(
        '<textarea name=\\\\"cert\\\\" rows=\\\\"8\\\\" cols=\\\\"70\\\\" style=\\\\"height: 120px\\\\">(?P<certificate>.*?)</textarea>')
    REQUEST_CERTIFICATE_CSR_ID = re.compile(
        'x_third_step_certs\(\\\\\'(?P<type>\w+?)\\\\\',\\\\\'(?P<csr_id>\d+?)\\\\\',\\\\\'(?P<unknown>.*?)\\\\\',showCertsWizard\);')
    REQUEST_CERTIFICATE_READY_CN = re.compile(
        '<li>The common name of this certificate will be set to <b><i>(?P<cn>.+?)</i></b>.</li>')
    REQUEST_CERTIFICATE_READY_DOMAINS = re.compile('<li><b><i>(?P<domain>.+?)</i></b></li>')
    REQUEST_CERTIFICATE_CERT = re.compile('<textarea.*?>(?P<certificate>.*?)</textarea>')
    VALIDATED_RESSOURCES = re.compile('<td nowrap>(?P<resource>.+?)</td><td nowrap> <img src="/img/yes-sm.png"></td>')

    def __init__(self, ca_certs=STARTCOM_CA):
        """
        Init the StartSSL API.

        :param ca_certs: PEM encoded CA certificate file to authenticate the server
        """
        self.h = httplib2.Http(ca_certs=ca_certs)
        self.validated_emails = None
        self.validated_domains = None
        self.authenticated = False
        self.cookies = None

    # noinspection PyShadowingNames
    def __request(self, *args, **kwargs):
        """
        Wrapper for HTTP requests
        """
        # make sure headers exist
        if "headers" not in kwargs:
            kwargs['headers'] = {}

        kwargs['headers']['User-Agent'] = "StartSSL_API/%s (+https://github.com/freddy36/StartSSL_API)" % __version__

        # add (overwrite) cookies
        if self.cookies:
            kwargs['headers']['Cookie'] = self.cookies

        # urlencode body if list
        if "body" in kwargs and type(kwargs['body']) is list:
            kwargs['body'] = urlencode(kwargs['body'])

        # add Content-Type: urlencoded if method is POST and content type is unset
        if "method" in kwargs and kwargs['method'] == "POST" and "Content-Type" not in kwargs['headers']:
            kwargs['headers']['Content-Type'] = "application/x-www-form-urlencoded"

        resp, content = self.h.request(*args, **kwargs)
        if resp.get("content-type", None) == 'text/html; charset=utf-8':
            content = content.decode('utf-8')

        return resp, content

    # noinspection PyShadowingNames
    def authenticate(self, cert, key):
        """
        Use the cert/key to authenticate the session.

        :param cert: path to pem encoded client certificate
        :param key: path to pem encoded client key
        :return: True on success
        """
        self.h.add_certificate(key, cert, '')
        resp, content = self.__request(self.STARTSSL_AUTHURI, method="POST", body="app=11")
        assert resp.status == 200
        assert "set-cookie" in resp
        assert resp["set-cookie"].startswith("STARTSSLID=")
        self.cookies = resp["set-cookie"]
        self.authenticated = True

        return self.authenticated

    def get_validated_resources(self, force_update=False):
        """
        Returns validated resources (emails/domains) which can be used in certificate requests.
        By default the data is only updated during the initial call. After that the cached data will be returned.

        :param force_update: Setting this to True will refresh the cache
        :return: [validated_emails], [self.validated_domains]
        """
        assert self.authenticated, "not authenticated"
        if self.validated_emails is not None and self.validated_domains is not None and not force_update:
            return self.validated_emails, self.validated_domains
        body = [('app', 12)]
        resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
        assert resp.status == 200
        items = self.VALIDATED_RESSOURCES.findall(content)
        self.validated_emails = []
        self.validated_domains = []
        for item in items:
            if '@' in item:
                self.validated_emails.append(item)
            else:
                self.validated_domains.append(item)
        return self.validated_emails, self.validated_domains

    def is_validated_domain(self, domain):
        """Check the validation status of a (sub)domain

        :param domain: (sub)domain to check
        :return: the validated (parent) domain or False
        """
        self.get_validated_resources()

        # noinspection PyTypeChecker
        for validated_domain in self.validated_domains:
            if domain.endswith(validated_domain):
                return validated_domain
        return False

    def get_certificates_list(self):
        """
        Returns the available signed certificates.

        Each certificate entry (dict) has the following keys:
        'id', 'name', 'class', 'profile', 'retrieved' (bool),
        'expires' (datetime), 'expires_day', 'expires_year', 'expires_month'

        :return: a list of certificate dicts
        """
        body = [('app', 12), ('rs', "set_toolbox_item"), ('rsargs[]', "crt")]
        resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
        assert resp.status == 200, "getCertificatesList bad status"
        assert "<b>Retrieve Certificate</b>" in content, "getCertificatesList unexpected content %s" % content

        items = self.RETRIEVE_CERTIFICATE_LIST.finditer(content)
        certs = []
        for item in items:
            cert = item.groupdict()

            # convert expire date
            cert['expires'] = datetime.date(int(cert['expires_year']), int(cert['expires_month']),
                                            int(cert['expires_day']))

            # convert id to integer
            cert['id'] = int(cert['id'])

            # convert profile description to profile identifier
            cert['profile'] = "unknown"
            for k, v in iter(self.CERTIFICATE_PROFILES.items()):
                if v == cert['profile_description']:
                    cert['profile'] = k
                    break
            del cert['profile_description']

            # set retrieved state depending on the background color
            if cert['color'] == "FFFFFF":
                cert['retrieved'] = True
            else:  # if color = rgb(201, 255, 196)
                cert['retrieved'] = False
            del cert['color']

            certs.append(cert)

        return certs

    def get_certificate(self, certificate_id):
        """
        Returns a certificate.

        Use get_certificates_list() to find the id or use the certificate_id returned by submit_certificate_request()

        TODO: can't retrieve S/MIME certificates yet

        :param certificate_id: StartSSL internal id of the certificate
        :return: PEM encoded certificate or None (invalid id)
        """

        body = [('app', 12), ('rs', "set_toolbox_item"), ('rsargs[]', "crt"), ('rsargs[]', certificate_id)]
        resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
        assert resp.status == 200, "getCertificate bad status"
        assert "<b>Retrieve Certificate</b>" in content, "getCertificate unexpected content %s" % content

        if "/getcrt.ssl?certID=" in content:
            # it's a S/MIME client certificate
            # resp, content = self.__request(self.STARTSSL_BASEURI+"/getcrt.ssl?certID=%i" % (certificate_id), method = "GET")
            # print resp, content
            raise NotImplementedError('S/MIME certificates are not supported.')
        else:
            # extract PEM encoded certificate
            item = self.RETRIEVE_CERTIFICATE_CERT.search(content)
            assert item, "no certificate found"
            cert = item.group('certificate')

            if len(cert) == 0:
                # invalid ID
                return None

            # replace newline escape sequences with actual newlines
            cert = cert.replace("\\n", "\n")
            cert = cert.strip()
            assert "-----BEGIN CERTIFICATE-----" in cert, "no BEGIN CERTIFICATE"
            assert "-----END CERTIFICATE-----" in cert, "no END CERTIFICATE"

            return cert

    def submit_certificate_request(self, profile, csr):
        """
        Submits a CSR.
        The common name and SubjectAltNames are extracted from the CSR.

        :param profile: the StartSSL profile which should be used (server or xmpp)
        :param csr: CSR instance
        :return: certificate_id (StartSSL internal id of the certificate),
                 common_name,
                 domains (dNSName SubjectAltNames),
                 certificate (PEM encoded certificate or None if manual approval by StartSSL is required
        """

        """"""
        assert profile in self.CERTIFICATE_PROFILES, "unknown profile"

        self.get_validated_resources()

        if profile in ['server', 'xmpp']:
            csr_cn = csr.get_common_name()
            subjects = [csr_cn]
            for t, v in csr.get_subject_alt_names(types=['dNSName']):
                if v not in subjects:
                    subjects.append(v)

            assert len(subjects) > 0, "no subjects found"

            subjects_direct = []
            subjects_subdomain = []
            validated_domain_first = None
            for subject in subjects:
                validated_domain = self.is_validated_domain(subject)
                if validated_domain:
                    if validated_domain not in subjects_direct:
                        subjects_direct.append(validated_domain)
                    if subject != validated_domain:
                        subjects_subdomain.append(subject)

                    if not validated_domain_first:
                        validated_domain_first = validated_domain
                else:
                    raise ValueError("Missing domain validations for %s." % subject)

            assert len(subjects_direct) > 0, "no direct subjects identified."

            # submit CSR
            body = [('app', 12), ('rs', 'second_step_certs'), ('rsargs[]', profile), ('rsargs[]', csr.get_pem())]
            resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
            assert resp.status == 200, "second_step_certs bad status"
            assert "<li>You submitted your certificate signing request successfully!.</li>" in content, "CSR submit failed"

            # extract CSR csr_id
            item = self.REQUEST_CERTIFICATE_CSR_ID.search(content)
            assert item, "no CSR csr_id found"
            assert profile == item.group('type'), "profile mismatch"
            certificate_id = int(item.group('csr_id'))

            # add primary (directly verified/drop down box) domains (using 3. rsarg of fourth_step_certs)
            for domain in subjects_direct:
                body = [('app', 12), ('rs', 'fourth_step_certs'), ('rsargs[]', profile), ('rsargs[]', certificate_id),
                        ('rsargs[]', domain), ('rsargs[]', '')]
                resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
                assert resp.status == 200, "fourth_step_certs bad status"

            # add subdomains (using 4. rsarg of fourth_step_certs)
            for domain in subjects_subdomain:
                body = [('app', 12), ('rs', 'fourth_step_certs'), ('rsargs[]', profile), ('rsargs[]', certificate_id),
                        ('rsargs[]', ''), ('rsargs[]', domain)]
                resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
                assert resp.status == 200, "fourth_step_certs bad status"

            # get ready page (list of all submitted domains)
            body = [('app', 12), ('rs', 'fifth_step_certs'), ('rsargs[]', profile), ('rsargs[]', certificate_id),
                    ('rsargs[]', ''), ('rsargs[]',
                                       '')]  # usually the last rsargs format is "."+validated_domain (empty text box with default drop down value), but apparently it's not used anyway
            resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
            assert resp.status == 200, "fifth_step_certs bad status"
            if "already exists" in content:
                raise ValueError("A certificate with the common name %s already exists" % csr_cn)
            assert "<li>We have gathered enough information in order to sign your certificate now.</li>" in content, "fifth_step_certs unexpected content %s" % (
                content)

            # extract common name
            item = self.REQUEST_CERTIFICATE_READY_CN.search(content)
            assert item, "no common name found"
            common_name = item.group('cn')
            assert common_name == csr_cn, "common name (%s) doesn't match the CSR common name (%s)" % (
                common_name, csr_cn)

            # extract domains
            domains = self.REQUEST_CERTIFICATE_READY_DOMAINS.findall(content)
            assert len(domains) > 0, "no domains found"
            assert set(subjects) <= set(domains), "domains (%s) don't include all CSR domains (%s)" % (
                str(domains), str(subjects))

            # finalize the request
            body = [('app', 12), ('rs', 'sixth_step_certs'), ('rsargs[]', profile), ('rsargs[]', certificate_id)]
            resp, content = self.__request(self.STARTSSL_BASEURI, method="POST", body=body)
            assert resp.status == 200, "sixth_step_certs bad status"

            if "In the textbox below is your PEM encoded certificate." in content:
                # this code path hasn't been tested yet
                item = self.REQUEST_CERTIFICATE_CERT.search(content)
                assert item, "no certificate found"
                cert = item.group('certificate')
                cert = cert.replace("\\n", "\n")
                assert "-----BEGIN CERTIFICATE-----" in cert, "no BEGIN CERTIFICATE"
                assert "-----END CERTIFICATE-----" in cert, "no END CERTIFICATE"
            elif "However your certificate request has been marked for approval by our personnel" in content:
                cert = None
            else:
                raise ValueError("Unexpected final return content: %s" % content)

            return certificate_id, common_name, domains, cert
        else:
            raise NotImplementedError('Only server/xmpp certificates are supported.')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="StartSSL_API", description="A CLI for some StartSSL functions.")
    parser.add_argument('--ca_certs', help='CA certificate file (PEM) to authenticate the server (default: %(default)s',
                        required=False, default=API.STARTCOM_CA, type=argparse.FileType('r'))
    parser.add_argument('--client_crt', help='Client certificate file (PEM)', required=True,
                        type=argparse.FileType('r'))
    parser.add_argument('--client_key', help='Client key file (PEM)', required=True, type=argparse.FileType('r'))
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

    subparsers = parser.add_subparsers(title='subcommands',
                                       description='valid subcommands, run them with -h for more details')
    parser_csr = subparsers.add_parser('csr', help='Submit a CSR')
    parser_csr.set_defaults(cmd="csr")
    parser_csr.add_argument('--profile', choices=['server', 'xmpp'], help='StartSSL profile', default="server",
                            type=str)
    parser_csr.add_argument('csr_files', nargs=argparse.REMAINDER, type=argparse.FileType('r'), help="CSR files (PEM)")
    parser_certs = subparsers.add_parser('certs', help='Retrieves signed certificates',
                                         description='Retrieves certificates from StartSSL. By default all available certificates are listed.')
    parser_certs.set_defaults(cmd="certs")
    parser_certs.add_argument('--store', action="append", choices=['all', 'new', 'missing'], default=[],
                              help="Retrieve all (replace any existing), new (never downloaded/green background), missing (target file missing) certificates")
    parser_certs.add_argument('--list_format',
                              default="{name}, {profile}, {class}, expires: {expires}, retrieved: {retrieved}, id: {id}",
                              type=str, help="default: %(default)s")
    parser_certs.add_argument('--filename_format', default="{name}.crt", type=str,
                              help="default: %(default)s, use - for stdout")
    parser_certs.add_argument('certificates', nargs=argparse.REMAINDER,
                              help="Retrieve specific certificates by name or id", type=str)
    args = parser.parse_args()

    api = API()
    api.authenticate(args.client_crt.name, args.client_key.name)
    if args.cmd == "certs":
        certs = api.get_certificates_list()
        if not args.store and not args.certificates:
            for cert in certs:
                print(args.list_format.format(**cert))
        else:
            for cert in certs:
                if not cert['profile'] in ['server', 'xmpp']:  # skip unsupported profiles
                    continue
                filename = args.filename_format.format(**cert)
                if (("all" in args.store) or
                        ("new" in args.store and not cert['retrieved']) or
                        ("missing" in args.store and not os.path.exists(filename)) or
                        (cert['name'] in args.certificates) or
                        (str(cert['id']) in args.certificates)):
                    cert = api.get_certificate(cert['id'])
                    if filename == "-":
                        print(cert)
                    else:
                        f = open(filename, 'w')
                        f.write(cert)
                        f.close()
                        print("stored", filename)
    elif args.cmd == "csr":
        for csr_file in args.csr_files:
            try:
                print("Submitting %s" % csr_file.name)
                csr = CSR(csr_file)
                certificate_id, common_name, subjects, cert = api.submit_certificate_request(profile=args.profile, csr=csr)
                if cert is None:
                    status = "pending for approval"
                else:
                    status = "certificate ready"
                print("Submission successful; id=%i; CN=%s; subjects=%s; %s" % (certificate_id, common_name, ", ".join(subjects), status))
                if cert:
                    print(cert)
            except ValueError as e:
                print("Submission failed:", e)
            except Exception as e:
                print("Submission failed:")
                print(traceback.format_exc(), file=sys.stderr)

    sys.exit(0)
