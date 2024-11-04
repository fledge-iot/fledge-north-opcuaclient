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


"""OPC UA Client North plugin"""

import asyncio
import json
from copy import deepcopy

from fledge.plugins.north.opcuaclient.client import _logger, AsyncClient

_LOGGER = _logger

__author__ = "Sebastian Kropatschek"
__copyright__ = "Copyright (c) 2021 Austrian Center for Digital Production (ACDP)"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"


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
    "security_mode": {
        "description": "Security Mode to use while connecting to OPCUA server",
        "type": "enumeration",
        "default": "None",
        "options": ["None", "Sign", "SignAndEncrypt"],
        'order': '4',
        'displayName': 'Security Mode',
        "group": "OPC UA Security"
    },
    "security_policy": {
        "description": "Security Policy to use while connecting to OPCUA server",
        "type": "enumeration",
        "default": "None",
        "options": ["None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128Sha256RsaOaep"],
        'order': '5',
        'displayName': 'Security Policy',
        "group": "OPC UA Security",
        "validity": "security_mode != \"None\""
    },
    "user_authentication_mode": {
        "description": "User authentication policy to use while connecting to OPCUA server",
        "type": "enumeration",
        "options": ["Anonymous", "Username And Password"],  # "Certificate", "IssuedToken"
        "displayName": "User Authentication Mode",
        "default": "Anonymous",
        "order": "6",
        "group": "OPC UA Security"
    },
    "username": {
        "description": "Username for the connection",
        "type": "string",
        "default": "",
        'order': '7',
        'displayName': 'Username',
        "group": "OPC UA Security",
        "validity": "user_authentication_mode == \"Username And Password\""
    },
    "password": {
        "description": "User Password for the connection.",
        "type": "password",
        "default": "",
        'order': '8',
        'displayName': 'Password',
        "group": "OPC UA Security",
        "validity": "user_authentication_mode == \"Username And Password\""
    },
    "server_certificate": {
        "description": "Server certificate file in DER or PEM format",
        "type": "string",
        "default": "",
        'order': '9',
        'displayName': 'Server Public Certificate',
        "group": "OPC UA Security",
        "validity": "security_mode != \"None\" && security_policy != \"None\""
    },
    "client_certificate": {
        "description": "Client certificate file either in DER or PEM format",
        "type": "string",
        "default": "",
        'order': '10',
        'displayName': 'Client Public Certificate',
        "group": "OPC UA Security",
        "validity": "security_mode != \"None\" && security_policy != \"None\""
    },
    "client_private_key": {
        "description": "Client private key file in PEM format",
        "type": "string",
        "default": "",
        'order': '11',
        'displayName': 'Client Private Key',
        "group": "OPC UA Security",
        "validity": "security_mode != \"None\" && security_policy != \"None\""
    },
    "client_private_key_passphrase": {
        "description": "Passphrase for client private key",
        "type": "password",
        "default": "",
        'order': '12',
        'displayName': 'Client Private Passphrase Key',
        "group": "OPC UA Security",
        "validity": "security_mode != \"None\" && security_policy != \"None\""
    }
}


def plugin_info():
    """Used only once when call will be made to a plugin
    Args:

    Returns:
        Information about the plugin including the configuration for the plugin
    """
    return {
        'name': 'OPC UA Client',
        'version': '2.6.0',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }


def plugin_init(data):
    """Used for initialization of a plugin
    Args:
        data: Plugin configuration
    Returns:
        Dictionary of a Plugin configuration
    """
    config_data = deepcopy(data)
    config_data['client'] = AsyncClient(config=config_data)
    return config_data


async def plugin_send(handle, payload, stream_id):
    """Used to send the readings block to the configured destination
    Args:
        handle: An object which is returned by plugin_init
        payload: A list of readings block
        stream_id: An integer that uniquely identifies the connection from Fledge instance to the destination system
    Returns:
          Tuple which consists of
          - A Boolean that indicates if any data has been sent
          - The object id of the last reading which has been sent
          - Total number of readings which has been sent to the configured destination
    """
    try:
        client = handle['client']
        is_data_sent, new_last_object_id, num_sent = await client.send_payloads(payload)
    except asyncio.CancelledError:
        pass
    else:
        return is_data_sent, new_last_object_id, num_sent


def plugin_shutdown(handle):
    """Used when plugin is no longer required and will be final call to the plugin
    Args:
        handle: An object which is returned by plugin_init
    Returns:
        None
    """
    client = handle['client']
    client.disconnect()
    handle['client'] = None


def plugin_reconfigure():
    pass

