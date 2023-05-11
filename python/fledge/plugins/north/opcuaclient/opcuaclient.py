# -*- coding: utf-8 -*-

# FLEDGE_BEGIN
# See: http://fledge.readthedocs.io/
# FLEDGE_END


# ***********************************************************************
# * DISCLAIMER:
# *
# * All sample code is provided by ACDP for illustrative purposes only.
# * These examples have not been thoroughly tested under all conditions.
# * ACDP provides no guarantee nor implies any reliability,
# * serviceability, or function of these programs.
# * ALL PROGRAMS CONTAINED HEREIN ARE PROVIDED TO YOU "AS IS"
# * WITHOUT ANY WARRANTIES OF ANY KIND. ALL WARRANTIES INCLUDING
# * THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY
# * AND FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY DISCLAIMED.
# ************************************************************************


""" OPC UA Client North plugin """

import asyncio
import json
import logging
from datetime import datetime
from copy import deepcopy

from asyncua import Client, ua
from asyncua.crypto.security_policies import SecurityPolicyBasic128Rsa15, SecurityPolicyBasic256, \
    SecurityPolicyBasic256Sha256

from fledge.common import logger
from fledge.common.common import _FLEDGE_ROOT, _FLEDGE_DATA


__author__ = "Sebastian Kropatschek"
__copyright__ = "Copyright (c) 2021 Austrian Center for Digital Production (ACDP)"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_LOGGER = logger.setup(__name__, level=logging.INFO)


_DEFAULT_CONFIG = {
    'plugin': {
         'description': 'OPC UA Client North Plugin',
         'type': 'string',
         'default': 'opcuaclient',
         'readonly': 'true'
    },
    'url': {
        'description': ' OPCUA Server URL',
        'type': 'string',
        'default': 'opc.tcp://mark.local:53530/OPCUA/SimulationServer',
        'order': '1',
        'displayName': 'OPC UA Server URL'
    },
    'map': {
        'description': 'A map for asset datapoints/attributes to OPC UA node objects',
        'type': 'JSON',
        'default': json.dumps({
            "sinusoid": {
                "sinusoid": {"node": "ns=1;i=51031", "type": "Double"},
            }
        }),
        'order': '2',
        'displayName': 'Map'
    },
    "source": {
         "description": "Source of data to be sent on the stream. May be either readings or statistics",
         "type": "enumeration",
         "default": "readings",
         "options": ["readings", "statistics"],
         'order': '3',
         'displayName': 'Source'
    },
    "authentication_mode": {
        "description": "User authentication mode",
        "type": "enumeration",
        "options": ["Anonymous", "Username And Password"],  # "Certificate", "IssuedToken"
        "displayName": "Authentication mode",
        "default": "Anonymous",
        "order": "4",
        "group": "Authentication"
    },
    "username": {
        "description": "Username for the connection",
        "type": "string",
        "default": "",
        'order': '5',
        'displayName': 'Username',
        "group": "Authentication",
        "validity": "authentication_mode == \"Username And Password\""
    },
    "password": {
        "description": "User Password for the connection.",
        "type": "password",
        "default": "",
        'order': '6',
        'displayName': 'Password',
        "group": "Authentication",
        "validity": "authentication_mode == \"Username And Password\""
    },
    "security_mode": {
        "description": "Security mode for the connection",
        "type": "enumeration",
        "default": "None",
        "options": ["None", "Sign", "SignAndEncrypt"],
        'order': '7',
        'displayName': 'Security Mode',
        "group": "Security"
    },
    "security_policy": {
        "description": "Security Policy for the connection",
        "type": "enumeration",
        "default": "Basic128Rsa15",
        "options": ["Basic128Rsa15", "Basic256", "Basic256Sha256"],
        'order': '8',
        'displayName': 'Security Policy',
        "group": "Security",
        "validity": "security_mode != \"None\""
    },
    "certificate": {
        "description": "Certificate Key Name and should have either in .der or .pem format",
        "type": "string",
        "default": "",
        'order': '9',
        'displayName': 'Certificate Name',
        "group": "Security",
        "validity": "security_mode != \"None\""
    },
    "private_key": {
        "description": "Private Key Name and should have either in .der or .pem format",
        "type": "string",
        "default": "",
        'order': '10',
        'displayName': 'Private Key Name',
        "group": "Security",
        "validity": "security_mode != \"None\""
    },
    "private_key_passphrase": {
        "description": "Passphrase for private key",
        "type": "password",
        "default": "",
        'order': '11',
        'displayName': 'Passphrase',
        "group": "Security",
        "validity": "security_mode != \"None\""
    }
}


def plugin_info():
    return {
        'name': 'OPC UA Client',
        'version': '2.1.0',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }


def plugin_init(data):
    config_data = deepcopy(data)
    config_data['opcua_client'] = OpcuaClientNorthPlugin(config=config_data)
    return config_data


async def plugin_send(handle, payload, stream_id):
    try:
        opcua_client = handle['opcua_client']
        is_data_sent, new_last_object_id, num_sent = await opcua_client.send_payloads(payload)
    except asyncio.CancelledError:
        pass
    else:
        return is_data_sent, new_last_object_id, num_sent


def plugin_shutdown(data):
    pass


def plugin_reconfigure():
    pass


class OpcuaClientNorthPlugin(object):

    def __init__(self, config):
        self.event_loop = asyncio.get_event_loop()
        self.map = config["map"]["value"]
        self.url = config["url"]["value"]
        self.authentication_mode = config["authentication_mode"]["value"]
        self.username = config["username"]["value"]
        self.password = config["password"]["value"]
        self.security_mode = config["security_mode"]["value"]
        self.security_policy = config["security_policy"]["value"]
        self.certificate = config["certificate"]["value"]
        self.private_key = config["private_key"]["value"]
        self.private_key_passphrase = config["private_key_passphrase"]["value"]

    async def send_payloads(self, payloads):
        is_data_sent = False
        last_object_id = 0
        num_sent = 0

        try:
            _LOGGER.debug('payloads size: {}'.format(len(payloads)))
            for p in payloads:
                asset_code = p['asset_code']
                last_object_id = p["id"]
                if asset_code in self.map:
                    for datapoint, item in self.map[asset_code].items():
                        if not (item.get('node') is None) and not (item.get('type') is None):
                            if datapoint in p['reading']:
                                read = {"value": p['reading'][datapoint], "type": item.get('type'),
                                        "node": item.get('node'), "timestamp": p['user_ts']}
                                await self._send_payloads(self.url, read)
                            else:
                                _LOGGER.debug("{} datapoint is missing in map configuration.".format(datapoint))
                        else:
                            _LOGGER.debug("For {} datapoint, either node or type KV pair is missing "
                                          "in map configuration.".format(datapoint))
                else:
                    _LOGGER.debug("{} asset code is missing in map configuration.".format(asset_code))
                num_sent += 1
            is_data_sent = True
        except ua.uaerrors.UaStatusCodeError as err:
            _LOGGER.error("Data could not be sent, %s", str(err))
        except Exception as ex:
            _LOGGER.exception("Data could not be sent, %s", str(ex))
        return is_data_sent, last_object_id, num_sent

    async def _send_payloads(self, url, payload_block):
        """ send a list of block payload """
        async with Client(url=url) as client:
            if self.authentication_mode != "Anonymous":
                client.set_user(self.username)
                client.set_password(self.password)
            if self.security_mode != "None":
                # Example:
                # Policy,Mode,certificate,private_key[,server_private_key]
                # "Basic256Sha256,Sign,certificate-example.der,private-key-example.pem")

                certificate = "{}/{}".format(self._get_certs_dir(), self.certificate)
                private_key = "{}/{}".format(self._get_certs_dir(), self.private_key)
                passphrase = "{}/{}".format(self._get_certs_dir(), self.private_key_passphrase)
                # client.set_security_string("{},{},{},{}".format(self.security_policy, self.security_mode, certificate, private_key))

                if self.security_policy == "Basic128Rsa15":
                    policy = SecurityPolicyBasic128Rsa15
                elif self.security_policy == "Basic256":
                    policy = SecurityPolicyBasic256
                else:
                    policy = SecurityPolicyBasic256Sha256

                if self.security_mode == "Sign":
                    mode = ua.MessageSecurityMode.Sign
                else:
                    mode = ua.MessageSecurityMode.SignAndEncrypt
                client.set_security(policy=policy,
                                    certificate=certificate,
                                    private_key=private_key,
                                    private_key_password=passphrase,
                                    server_certificate=None,  # FIXME: If required server cert
                                    mode=mode)

            var = client.get_node(payload_block["node"])
            user_ts = datetime.strptime(payload_block["timestamp"], '%Y-%m-%d %H:%M:%S.%f%z')
            data_value = ua.DataValue(Value=self._value_to_variant(payload_block["value"], payload_block["type"]),
                                      SourceTimestamp=user_ts)
            await var.write_value(data_value)

    def _value_to_variant(self, value, type_):
        type_ = type_.strip().lower()

        if type_ == "bool":
            return self._value_to_variant_type(value, self._bool, ua.VariantType.Boolean)
        elif type_ == "sbyte":
            return self._value_to_variant_type(value, int, ua.VariantType.SByte)
        elif type_ == "byte":
            return self._value_to_variant_type(value, int, ua.VariantType.Byte)
        elif type_ == "uint16":
            return self._value_to_variant_type(value, int, ua.VariantType.UInt16)
        elif type_ == "uint32":
            return self._value_to_variant_type(value, int, ua.VariantType.UInt32)
        elif type_ == "uint64":
            return self._value_to_variant_type(value, int, ua.VariantType.UInt64)
        elif type_ == "int16":
            return self._value_to_variant_type(value, int, ua.VariantType.Int16)
        elif type_ == "int32":
            return self._value_to_variant_type(value, int, ua.VariantType.Int32)
        elif type_ == "int64":
            return self._value_to_variant_type(value, int, ua.VariantType.Int64)
        elif type_ == "float":
            return self._value_to_variant_type(value, float, ua.VariantType.Float)
        elif type_ == "double":
            return self._value_to_variant_type(value, float, ua.VariantType.Double)
        elif type_ == "string":
            return self._value_to_variant_type(value, str, ua.VariantType.String)
        # elif type_ == "datetime":
        #    raise NotImplementedError
        # elif type_ == "Guid":
        #    return self._value_to_variant_type(value, bytes, ua.VariantType.Guid)
        elif type_ == "ByteString":
            return self._value_to_variant_type(value, bytes, ua.VariantType.ByteString)
        # elif type_ == "xml":
        #    return self._value_to_variant_type(value, str, ua.VariantType.XmlElement)
        # elif type_ == "nodeid":
        #    return self._value_to_variant_type(value, ua.NodeId.from_string, ua.VariantType.NodeId)
        # elif type_ == "expandednodeid":
        #    return self._value_to_variant_type(value, ua.ExpandedNodeId.from_string, ua.VariantType.ExpandedNodeId)
        # elif type_ == "statuscode":
        #    return self._value_to_variant_type(value, int, ua.VariantType.StatusCode)
        # elif type_ in ("qualifiedname", "browsename"):
        #    return self._value_to_variant_type(value, ua.QualifiedName.from_string, ua.VariantType.QualifiedName)
        elif type_ == "LocalizedText":
            return self._value_to_variant_type(value, ua.LocalizedText, ua.VariantType.LocalizedText)

    def _value_to_variant_type(self, value, ptype, varianttype=None):
        # FIXME:
        # if isinstance(value, (list, tuple)
        if isinstance(value, list):
            value = [ptype(i) for i in value]
        else:
            value = ptype(value)

        if varianttype:
            return ua.Variant(value, varianttype)
        else:
            return ua.Variant(value)

    def _bool(self, value):
        if value in (True, "True", "true", 1, "1"):
            return True
        if value in (False, "False", "false", 0, "0"):
            return False
        else:
            return bool(value)

    def _get_certs_dir(self, _path="/etc/certs/"):
        dir_path = _FLEDGE_DATA + _path if _FLEDGE_DATA else _FLEDGE_ROOT + '/data' + _path
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        certs_dir = os.path.expanduser(dir_path)
        return certs_dir

