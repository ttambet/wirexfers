# -*- coding: utf-8 -*-
"""
    wirexfers.protocols.hire
    ~~~~~~~~~~~~~~~~~~~~~~~~

    LHV hire banklink implementations.

    :copyright: (c) 2016, Timo Tambet
    :license: ISC, see LICENSE for more details.
"""
from datetime import datetime, timedelta
from base64 import b64encode
import time

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

from . import KeyChainBase, ProviderBase
from .. import PaymentResponse
from ..exc import InvalidResponseError

class EELHVProvider(ProviderBase):
    """LHV IPizza hire banklink provider.
    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaKeyChain`
    Supported return kwargs:
        * ``xml`` ``response`` ``return`` ``email`` ``phone``
    Supported protocol version:
        * ``008``
    """
    form_charset = 'UTF-8'

    class KeyChain(KeyChainBase):

        def __init__(self, private_key, public_key):
            #: RSA private key (:py:class:`Crypto.PublicKey.RSA._RSAobj`) object.
            #: See :func:`wirexfers.utils.load_key`.
            self.private_key = private_key

            #: RSA public key (:py:class:`Crypto.PublicKey.RSA._RSAobj`) object
            #: See :func:`wirexfers.utils.load_key`.
            self.public_key = public_key

    def _sign_request(self, info, kwargs):
        """Create and sign LHV hire request data."""
        fields = [('VK_SERVICE',  u'5011'),
                  ('VK_VERSION',  u'008'),
                  ('VK_SND_ID',   self.user),
                  ('VK_REC_ID',   'LHV'),
                  ('VK_STAMP',    '%d' % int(time.time())),
                  ('VK_DATA',     kwargs['xml']),
                  ('VK_RESPONSE', kwargs['response']),
                  ('VK_RETURN',   kwargs['return']),
                  ('VK_DATETIME', time.strftime('%Y-%m-%dT%H:%M:%S%z')),
                  ('VK_EMAIL',    kwargs.get('email', '')),
                  ('VK_PHONE',    kwargs.get('phone', ''))]

        # MAC calculation for request 5011
        m = self._build_mac(('SERVICE', 'VERSION', 'SND_ID', 'REC_ID', 'STAMP', \
                             'DATA', 'RESPONSE', 'RETURN', 'DATETIME', 'EMAIL', 'PHONE'), dict(fields))

        # Append mac fields
        fields.append(('VK_MAC', b64encode( \
                    PKCS1_v1_5.new(self.keychain.private_key)
                              .sign(SHA.new(m)))))
        return fields

    def parse_response(self, form, success=True):
        """Parse and return LHV hire response."""

        fields = ['5111', '5112', '5113']

        # See which response we got
        resp = code = form.get('VK_SERVICE', None)
        if not resp and resp not in fields:
            raise InvalidResponseError

        success = resp in fields
        Random.atfork()

        # Parse and validate date
        f = lambda x: form.get('VK_%s' % x)
        t = datetime.strptime(f('DATETIME').split('+')[0], "%Y-%m-%dT%H:%M:%S")

        if datetime.now() - timedelta(seconds=300) > t:
            raise InvalidResponseError

        # Save hire response data
        data = {} if not success else {'data': f('DATA'), 'code': code}

        return PaymentResponse(self, data, success)

    @staticmethod
    def _build_mac(fields, data):
        """Build MAC string ('0045011003008') for required fields."""
        f = lambda x: data.get('VK_%s' % x)
        return u''.join(map(lambda k: '%03d%s' % (len(f(k)), f(k)), fields)).encode('utf-8')
