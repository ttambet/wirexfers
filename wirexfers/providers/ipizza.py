# -*- coding: utf-8 -*-
"""
    wirexfers.protocols.ipizza
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    IPizza protocol implementations.

    :copyright: (c) 2012-2014, Priit Laes
    :license: ISC, see LICENSE for more details.
"""
from base64 import b64encode, b64decode

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

from . import KeyChainBase, ProviderBase
from .. import PaymentResponse
from ..exc import InvalidResponseError
import requests

from datetime import datetime, timedelta
import time
from dateutil.parser import parse
import pytz

class IPizzaProviderBase(ProviderBase):
    """Base class for IPizza protocol provider.

    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaKeyChain`
    Supported return urls:
        * ``return``
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

    def _sign_request(self, info, return_urls):
        """Create and sign payment request data."""
        # Basic fields
        fields = [('VK_SERVICE',  u'1012'),
                  ('VK_VERSION',  u'008'),
                  ('VK_SND_ID',   self.user),
                  ('VK_STAMP',    '%d' % int(time.time())),
                  ('VK_AMOUNT',   info.amount),
                  ('VK_CURR',     u'EUR'),
                  ('VK_DATETIME', time.strftime('%Y-%m-%dT%H:%M:%S%z')),
                  ('VK_REF',      info.refnum),
                  ('VK_MSG',      info.message)]

        # Check whether provider supplies extra fields
        if hasattr(self, 'extra_fields'):
            fields.extend(self.extra_fields)

        # Append return url field(s)
        fields.append(('VK_RETURN', return_urls['return']))
        fields.append(('VK_CANCEL', return_urls['cancel']))

        ## MAC calculation for request 1012
        m = self._build_mac(('SERVICE', 'VERSION', 'SND_ID', 'STAMP', \
                             'AMOUNT', 'CURR', 'REF', 'MSG', 'RETURN', \
                             'CANCEL', 'DATETIME'), dict(fields))
        # Append mac fields
        fields.append(('VK_MAC', b64encode( \
                    PKCS1_v1_5.new(self.keychain.private_key)
                              .sign(SHA.new(m)))))

        return fields

    def parse_response(self, form, success=True):
        """Parse and return payment response."""
        fields = {
            # Successful payment
            '1111': ('SERVICE', 'VERSION', 'SND_ID', 'REC_ID', 'STAMP', #  1..5
                     'T_NO', 'AMOUNT', 'CURR', 'REC_ACC', 'REC_NAME',   #  6..10
                     'SND_ACC', 'SND_NAME', 'REF', 'MSG', 'T_DATETIME'),# 11..15
            # Unsuccessful payment
            '1911': ('SERVICE', 'VERSION', 'SND_ID', 'REC_ID', 'STAMP', #  1..5
                     'REF', 'MSG')                                      #  6..7
        }
        # See which response we got
        resp = form.get('VK_SERVICE', None)
        if not resp and resp not in fields:
            raise InvalidResponseError
        success = resp == '1111'

        Random.atfork()

        # Parse and validate MAC
        m = self._build_mac(fields[resp], form)
        f = lambda x: form.get('VK_%s' % x)
        if not PKCS1_v1_5.new(self.keychain.public_key) \
                         .verify(SHA.new(m), b64decode(f('MAC'))):
            raise InvalidResponseError

        # Parse reponse
        d = parse(f('T_DATETIME')).astimezone(pytz.utc)

        # Current time (UTC)
        now = datetime.now(pytz.utc)

        # Timedelta 5 min
        td = timedelta(seconds=300)
        if not ((now - td) < d < (now + td)):
            # FIXME: Python 3 should support Timeout exception
            raise requests.exceptions.Timeout

        # Save payment data
        data = {}
        if success:
            for item in ('T_NO', 'AMOUNT', 'CURR', 'REC_ACC', 'REC_NAME',
                         'SND_ACC', 'SND_NAME', 'REF', 'MSG', 'T_DATETIME'):
                data[item] = f(item)
        return PaymentResponse(self, data, success)

    @staticmethod
    def _build_mac(fields, data):
        """Build MAC string ('003one003two') for required fields."""
        f = lambda x: data.get('VK_%s' % x)
        return u''.join(map(lambda k: '%03d%s' % (len(f(k)),
            f(k)), fields)).encode('utf-8')

class EEDanskeProvider(IPizzaProviderBase):
    """
    | Danske Bank A/S Eesti filiaal
    | http://www.danskebank.ee

    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaProviderBase.KeyChain`
    Supported return urls:
        * ``return``
    Supported protocol version:
        * ``008``
    """
    form_charset = 'ISO-8859-1'

    @staticmethod
    def _build_mac(fields, data):
        """Build MAC string. Length is in bytes instead of symbols."""
        f = lambda x: data.get('VK_%s' % x).encode('latin', 'ignore')
        return ''.join(map(lambda k: '%03d%s' % (len(f(k)), f(k)), fields))

class EEKrediidipankProvider(IPizzaProviderBase):
    """
    | AS Eesti Krediidipank
    | http://krediidipank.ee/

    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaProviderBase.KeyChain`
    Supported return urls:
        * ``return``
    Supported protocol version:
        * ``008``
    """
    extra_fields = (('VK_CHARSET', 'UTF-8'),)

    @staticmethod
    def _build_mac(fields, data):
        """Build MAC string. Length is in bytes instead of symbols."""
        f = lambda x: data.get('VK_%s' % x)
        return u''.join(map(lambda k: '%03d%s' % (len(f(k)), f(k)), fields)).encode('utf-8')

class EELHVProvider(IPizzaProviderBase):
    """
    | AS LHV Pank
    | https://www.lhv.ee

    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaProviderBase.KeyChain`
    Supported return urls:
        * ``return``
    Supported protocol version:
        * ``008``
    """
    extra_fields = (('VK_CHARSET', 'UTF-8'),)


class EESEBProvider(IPizzaProviderBase):
    """
    | AS SEB Pank
    | http://www.seb.ee

    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaProviderBase.KeyChain`
    Supported return urls:
        * ``return``
    Supported protocol version:
        * ``008``
    """
    extra_fields = (('VK_CHARSET', 'UTF-8'),)


class EESwedBankProvider(IPizzaProviderBase):
    """
    | SWEDBANK AS
    | https://www.swedbank.ee

    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaProviderBase.KeyChain`
    Supported return urls:
        * ``return``
    Supported protocol version:
        * ``008``
    """
    extra_fields = (('VK_CHARSET', 'UTF-8'),)


class EENordeaProvider(IPizzaProviderBase):
    """
    | Nordea Bank Finland Plc Eesti / AS Nordea Finance Estonia
    | https://www.nordea.ee

    Protocol
        IPizza
    KeyChain
        :class:`~.IPizzaProviderBase.KeyChain`
    Supported return urls:
        * ``return``
    Supported protocol version:
        * ``008``
    """
    extra_fields = (('VK_ENCODING', 'UTF-8'),)
