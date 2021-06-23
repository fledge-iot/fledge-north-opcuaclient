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
                "sinusoid": {"node": "ns=1;i=51031", "type": "Double"},
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

        map = json.loads(handle['map']['value'])

        try:
            _LOGGER.info('processing payloads')
            payload_block = list()

            for p in payloads:
                last_object_id = p["id"]

                if p['asset_code'] in map:
                    for datapoint, item in map[p['asset_code']].items():
                        if not (item.get('node') is None) and not (item.get('type') is None):
                            if datapoint in p['reading']:
                                read = dict()
                                read["value"] = p['reading']['datapoint']
                                read["type"] = item.get('type')
                                read["node"] = item.get('node')
                                read["timestamp"] = p['user_ts']
                                await self._send_payloads(read)
            num_sent+=1
        else:
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

            var = client.get_node(payload_block["node"])

            print("My variable", var, await var.read_value())
            #await var.write_value(ua.DataValue(value_to_variant(value, payload_block["type"]), SourceTimestamp=datetime.utcnow()))
            await var.write_value(value_to_variant(value, payload_block["type"])) #set node value using explicit data type
            print("My variable", var, await var.read_value())








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

    def _value_to_variant(value, type_):
        type_ = type_.strip().lower()

        if type_ == "bool":
            return _value_to_variant_type(value, _bool, ua.VariantType.Boolean)
        elif type_ == "sbyte":
            return _value_to_variant_type(value, int, ua.VariantType.SByte)
        elif type_ == "byte":
            return _value_to_variant_type(value, int, ua.VariantType.Byte)
        elif type_ == "uint16":
            return _value_to_variant_type(value, int, ua.VariantType.UInt16)
        elif type_ == "uint32":
            return _value_to_variant_type(value, int, ua.VariantType.UInt32)
        elif type_ == "uint64":
            return _value_to_variant_type(value, int, ua.VariantType.UInt64)
        elif type_ == "int16":
            return _value_to_variant_type(value, int, ua.VariantType.Int16)
        elif type_ == "int32":
            return _value_to_variant_type(value, int, ua.VariantType.Int32)
        elif type_ == "int64":
            return _value_to_variant_type(value, int, ua.VariantType.Int64)
        elif type_ == "float":
            return _value_to_variant_type(value, float, ua.VariantType.Float)
        elif type_ == "double":
            return _value_to_variant_type(value, float, ua.VariantType.Double)
        elif type_ == "string":
            return _value_to_variant_type(value, str, ua.VariantType.String)
        #elif type_ == "datetime":
        #    raise NotImplementedError
        #elif type_ == "Guid":
        #    return _value_to_variant_type(value, bytes, ua.VariantType.Guid)
        elif type_ == "ByteString":
            return _value_to_variant_type(value, bytes, ua.VariantType.ByteString)
        #elif type_ == "xml":
        #    return _value_to_variant_type(value, str, ua.VariantType.XmlElement)
        #elif type_ == "nodeid":
        #    return _value_to_variant_type(value, ua.NodeId.from_string, ua.VariantType.NodeId)
        #elif type_ == "expandednodeid":
        #    return _value_to_variant_type(value, ua.ExpandedNodeId.from_string, ua.VariantType.ExpandedNodeId)
        #elif type_ == "statuscode":
        #    return _value_to_variant_type(value, int, ua.VariantType.StatusCode)
        #elif type_ in ("qualifiedname", "browsename"):
        #    return _value_to_variant_type(value, ua.QualifiedName.from_string, ua.VariantType.QualifiedName)
        elif type_ == "LocalizedText":
            return _value_to_variant_type(value, ua.LocalizedText, ua.VariantType.LocalizedText)


    def _value_to_variant_type(value, ptype, varianttype=None):
        #FIXME
        # if isinstance(value, (list, tuple)
        if isinstance(value, list):
            value = [ptype(i) for i in value]
        else:
            value = ptype(value)

        if varianttype:
            return ua.Variant(value, varianttype)
        else:
            return ua.Variant(value)


    def _bool(value):
        if value in (True, "True", "true", 1, "1"):
            return True
        if value in (False, "False", "false", 0, "0"):
            return False
        else:
            bool(value)
