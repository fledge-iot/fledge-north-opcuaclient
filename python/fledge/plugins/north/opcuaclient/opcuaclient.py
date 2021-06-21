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


""" OpcuaClient North plugin"""
import asyncio
import time
import json
import sys

# Using the Python OpcuaClient
# https://github.com/OpcuaClient/opcuaclient-iot-sdk-python
# python min requirment python 3.7
#from asyncua import Client
from opcua import Client

from fledge.common import logger
from fledge.plugins.north.common.common import *

__author__ = "Sebastian Kropatschek"
__copyright__ = "Copyright (c) 2021 Austrian Center for Digital Production (ACDP)"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_LOGGER = logger.setup(__name__)

_CONFIG_CATEGORY_NAME = "OPCUACLIENT"
_CONFIG_CATEGORY_DESCRIPTION = "OpcuaClient Python North Plugin"

_DEFAULT_CONFIG = {
    'plugin': {
         'description': 'Opcua Client North Plugin',
         'type': 'string',
         'default': 'opcuaclient',
         'readonly': 'true'
    },
    'url': {
        'description': ' OPCUA Server URL',
        'type': 'string',
        'default': 'opc.tcp://mark.local:53530/OPCUA/SimulationServer',
        'order': '1',
        'displayName': 'Primary Connection String'
    },
    'map': {
        'description': 'map',
        'type': 'JSON',
        'default': json.dumps({
            "sinusoid": {
                "sinusoid": {"node": "", "type": ""},
            }
        }),
        'order': '2',
        'displayName': 'Register Map'
    },
    "source": {
         "description": "Source of data to be sent on the stream. May be either readings or statistics.",
         "type": "enumeration",
         "default": "readings",
         "options": [ "readings", "statistics" ],
         'order': '3',
         'displayName': 'Source'
    },
    "applyFilter": {
        "description": "Should filter be applied before processing data",
        "type": "boolean",
        "default": "false",
        'order': '4',
        'displayName': 'Apply Filter'
    },
    "filterRule": {
        "description": "JQ formatted filter to apply (only applicable if applyFilter is True)",
        "type": "string",
        "default": ".[]",
        'order': '5',
        'displayName': 'Filter Rule',
        "validity": "applyFilter == \"true\""
    }
}

def plugin_info():
    return {
        'name': 'opcuaclient',
        'version': '1.9.1',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }

def plugin_init(data):
    _LOGGER.info('Initializing OpcuaClient North Python Plugin')
    global opcuaclient_north, config
    opcuaclient_north = OpcuaClientNorthPlugin()
    config = data
    _LOGGER.info(f'Initializing plugin with Primary Connection String: {config["url"]["value"]}')
    return config

async def plugin_send(data, payload, stream_id):
    try:
        _LOGGER.info(f'OpcuaClient North Python - plugin_send: {stream_id}')
        is_data_sent, new_last_object_id, num_sent = await opcuaclient_north.send_payloads(payload)
    except asyncio.CancelledError as ex:
        _LOGGER.exception(f'Exception occurred in plugin_send: {ex}')
    else:
        _LOGGER.info('payload sent successfully')
        return is_data_sent, new_last_object_id, num_sent

def plugin_shutdown(data):
    pass

# TODO: North plugin can not be reconfigured? (per callback mechanism)
def plugin_reconfigure():
    pass

class OpcuaClientNorthPlugin(object):
    """ North Opcua Client Plugin """

    def __init__(self):
        self.event_loop = asyncio.get_event_loop()

    def opcuaclient_error(self, error):
        _LOGGER.error(f'OpcuaClient error: {error}')

    async def send_payloads(self, payloads):
        is_data_sent = False
        last_object_id = 0
        num_sent = 0

        size_payload_block = 0

        try:
            _LOGGER.info('processing payloads')
            payload_block = list()

            for p in payloads:
                read = dict()
                read["asset"] = p['asset_code']
                read["readings"] = p['reading']
                read["timestamp"] = p['user_ts']

                last_object_id = p["id"]
                payload_block.append(read)

            num_sent = await self._send_payloads(payload_block)
            _LOGGER.info('payloads sent: {num_sent}')
            is_data_sent = True
        except Exception as ex:
            _LOGGER.exception("Data could not be sent, %s", str(ex))

        return is_data_sent, last_object_id, num_sent

    async def _send_payloads(self, payload_block):
        """ send a list of block payloads"""

        num_count = 0

        client = Client(config["url"]["value"])
        # client = Client("opc.tcp://admin@localhost:4840/freeopcua/server/") #connect using a user
        try:
            client.connect()

            # Client has a few methods to get proxy to UA nodes that should always be in address space such as Root or Objects
            #root = client.get_root_node()
            #print("Objects node is: ", root)

            # Node objects have methods to read and write node attributes as well as browse or populate address space
            #print("Children of root are: ", root.get_children())

            # get a specific node knowing its node id
            #var = client.get_node(ua.NodeId(1002, 2))
            #var = client.get_node("ns=3;i=2002")
            #print(var)
            #var.get_data_value() # get value of node as a DataValue object
            #var.get_value() # get value of node as a python builtin
            #var.set_value(ua.Variant([23], ua.VariantType.Int64)) #set node value using explicit data type
            #var.set_value(3.9) # set node value using implicit data type

            # Now getting a variable node using its browse path
            #myvar = root.get_child(["0:Objects", "2:MyObject", "2:MyVariable"])
            #obj = root.get_child(["0:Objects", "2:MyObject"])
            #print("myvar is: ", myvar)
            #print("myobj is: ", obj)

            # Stacked myvar access
            # print("myvar is: ", root.get_children()[0].get_children()[1].get_variables()[0].get_value())

        except Exception as ex:
            _LOGGER.exception(f'Exception sending payloads: {ex}')
        else:
            num_count += len(payload_block)
        finally:
            client.disconnect()

        return num_count

    async def _send(self, client, payload):
        """ Send the payload, using provided client """

        await client.send_message(message)
        _LOGGER.info('Message successfully sent')
