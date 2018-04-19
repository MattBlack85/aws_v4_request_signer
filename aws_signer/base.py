# -*- coding: utf-8 -*-
import datetime
import hashlib
import hmac
import os
from urllib.parse import quote_plus


class AbstractAWSSigner:
    """
    Abstraction of a AWS signer to sign a url to take an API action
    """
    service = ''
    host = ''
    algorithm = 'AWS4-HMAC-SHA256'

    def __init__(self, method='GET', region='eu-west-1', api_version='2012-05-11', **kwargs):
        self.method = method
        self.region = region
        t = datetime.datetime.utcnow()
        self.amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = t.strftime('%Y%m%d')
        self.canonical_uri = self._generate_canonical_uri()
        self.endpoint = f'https://{self.service}.{region}.amazonaws.com{self.canonical_uri}'
        self.access_key = None
        self.secret_key = None
        self.credential_scope = f'{self.datestamp}/{self.region}/{self.service}/aws4_request'
        self.api_version = api_version
        self.get_credentials()

    def get_credentials(self):
        self.access_key = os.environ.get('AWS_ACCESS_KEY')
        self.secret_key = os.environ.get('AWS_SECRET_KEY')

    def _sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    @property
    def signing_key(self):
        """
        Forge the signing key from:
         - the AWS secret key
         - a timestamp string indicating at was time the request was signed
         - the service region
         - the type of request (aws4_request)
        """
        signed_date = self._sign(('AWS4' + self.secret_key).encode('utf-8'), self.datestamp)
        signed_region = self._sign(signed_date, self.region)
        signed_service = self._sign(signed_region, self.service)
        signing_key = self._sign(signed_service, 'aws4_request')
        return signing_key

    def generate_payload_hash(self, payload):
        if not isinstance(payload, bytes):
            payload = payload.encode()
        return hashlib.sha256(payload).hexdigest()

    def generate_canonical_uri(self):
        """
        Method to be overridden by concrete implementations, this should return the canonical uri
        aka the URL part from domain to query params.

        For example the canonical uri for https://service.aws.com/{account_id}/{target_object}/?QueryParams=foo
        would be /{account_id}/{target_object}/
        """  # NOQA
        return NotImplemented

    def generate_query_params(self):
        return NotImplemented

    def generate_canonical_headers(self):
        return NotImplemented

    def get_signed_headers(self):
        """
        Return a string with the signed headers that will be checked by AWS.
        Usually for GET requests the signed header is just `host`.
        """
        return NotImplemented

    def _build_payload(self):
        """
        This method must be overridden to provide the request payload, note that for GET requests
        an empty payload b'' is expected.
        """
        return NotImplemented

    def _sort_querystring(self, querystring):
        return sorted(querystring.split('&'))


class AWSGETQueryParamsSigner(AbstractAWSSigner):
    """
    Class to be used when GET requests with auth credentials in the query params
    need to be used.
    """

    def generate_canonical_uri(self):
        return '/'

    def generate_query_params(self, **kwargs):
        raise NotImplementedError()

    def generate_canonical_headers(self):
        raise NotImplementedError()

    def get_signed_headers(self):
        return 'host'

    def _build_payload(self):
        return b''

    def build_canonical_request(self, payload_hash, canonical_querystring):
        return (f'{self.method}\n{self.canonical_uri}\n{canonical_querystring}\n'
                f'{self.generate_canonical_headers()}\n{self.get_signed_headers()}\n{payload_hash}')  # NOQA

    def generate_canonical_querystring(self, **kwargs):
        credentials = f'{self.access_key}/{self.credential_scope}'
        canonical_querystring = self._generate_query_params(**kwargs)
        canonical_querystring += f'&X-Amz-Algorithm={self.algorithm}'
        canonical_querystring += f'&X-Amz-Credential={quote_plus(credentials)}'
        canonical_querystring += f'&X-Amz-Date={self.amz_date}'
        canonical_querystring += f'&X-Amz-SignedHeaders={self.get_signed_headers()}'

        return canonical_querystring

    def generate_url(self, **kwargs):
        canonical_querystring = self.generate_canonical_querystring(**kwargs)
        payload = self._build_payload()
        payload_hash = self.generate_payload_hash(payload)
        canonical_request = self.build_canonical_request(payload_hash, canonical_querystring)

        string_to_sign = (f'{self.algorithm}\n{self.amz_date}\n{self.credential_scope}\n'
                          f'{hashlib.sha256(canonical_request.encode()).hexdigest()}')

        signature = hmac.new(self.signing_key,
                             string_to_sign.encode(),
                             hashlib.sha256).hexdigest()

        canonical_querystring += f'&X-Amz-Signature={signature}'
        sorted_canonical_querystring = self._sort_querystring(canonical_querystring)
        return f'{self.endpoint}?{sorted_canonical_querystring}'
