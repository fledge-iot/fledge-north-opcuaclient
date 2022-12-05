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


""" OpcuaClient North plugin """

import asyncio
import json
import logging
from datetime import datetime

from asyncua import Client, Node, ua
from fledge.common import logger
from fledge.plugins.north.common.common import *

__author__ = "Sebastian Kropatschek"
__copyright__ = "Copyright (c) 2021 Austrian Center for Digital Production (ACDP)"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_LOGGER = logger.setup(__name__, level=logging.INFO)


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
         "options": ["readings", "statistics"],
         'order': '3',
         'displayName': 'Source'
    }
}


def plugin_info():
    return {
        'name': 'OPCUA Client',
        'version': '2.0.1',
        'type': 'north',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }


def plugin_init(data):
    global opcuaclient_north, config
    opcuaclient_north = OpcuaClientNorthPlugin()
    config = data
    return config


async def plugin_send(data, payload, stream_id):
    try:
        is_data_sent, new_last_object_id, num_sent = await opcuaclient_north.send_payloads(payload)
    except asyncio.CancelledError as ex:
        _LOGGER.exception(f'Exception occurred in plugin_send: {ex}')
    else:
        _LOGGER.debug('payload sent successfully')
        return is_data_sent, new_last_object_id, num_sent


def plugin_shutdown(data):
    pass


def plugin_reconfigure():
    pass


class OpcuaClientNorthPlugin(object):
    """ North Opcua Client Plugin """

    def __init__(self):
        self.event_loop = asyncio.get_event_loop()

    async def send_payloads(self, payloads):
        is_data_sent = False
        last_object_id = 0
        num_sent = 0

        try:
            _map = config['map']['value']
            _LOGGER.debug('processing payloads: {}'.format(payloads))
            _LOGGER.debug('map: {}'.format(_map))

            for p in payloads:
                last_object_id = p["id"]
                if p['asset_code'] in _map:
                    for datapoint, item in _map[p['asset_code']].items():
                        if not (item.get('node') is None) and not (item.get('type') is None):
                            if datapoint in p['reading']:
                                read = dict()
                                read["value"] = p['reading'][datapoint]
                                read["type"] = item.get('type')
                                read["node"] = item.get('node')
                                read["timestamp"] = p['user_ts']
                                _LOGGER.debug("Time: %s", str(p['user_ts']))

                                await self._send_payloads(read)
                                
                                num_sent += 1
            _LOGGER.info('payloads sent: {num_sent}'.format(num_sent=num_sent))
            is_data_sent = True
        except Exception as ex:
            _LOGGER.exception("Data could not be sent, %s", str(ex))

        return is_data_sent, last_object_id, num_sent

    async def _send_payloads(self, payload_block):
        """ send a list of block payloads"""
        async with Client(url=config["url"]["value"]) as client:
            var = client.get_node(payload_block["node"])

            # _LOGGER.warn("My variable old value %s", await var.read_value())
            datavalue = ua.DataValue(Value=self._value_to_variant(payload_block["value"], payload_block["type"]),
                                     SourceTimestamp=datetime.utcnow())
            # _LOGGER.warn("check timestamp %s", datetime.fromisoformat(payload_block["timestamp"]).strftime('%Y-%m-%d %H:%M:%S. %f'))
            await var.write_value(datavalue)
            # await var.write_value(self._value_to_variant(payload_block["value"], payload_block["type"])) #set node value using explicit data type
            # _LOGGER.warn("My variable  new value %s", await var.read_value())
        # num_count = 0

        # client = Client(config["url"]["value"])
        # client = Client("opc.tcp://admin@localhost:4840/freeopcua/server/") #connect using a user
        # try:
            # client.connect()

            # _LOGGER.warn("payload %s", str(payload_block))

            # var = client.get_node(payload_block["node"])

            # _LOGGER.warn("My variable before write %s", str(await var.read_value()))
            # await var.write_value(ua.DataValue(value_to_variant(value, payload_block["type"]), SourceTimestamp=datetime.utcnow()))
            # await var.write_value(self._value_to_variant(payload_block["value"], payload_block["type"])) #set node value using explicit data type
            # _LOGGER.warn("My variable after write %s %s", str(var), str(await var.read_value()))

        # except Exception as ex:
            # _LOGGER.exception(f'Exception sending payloads: {ex}')
        # else:
            # num_count += len(payload_block)
        # finally:
            # client.disconnect()

        # return num_count

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
            bool(value)
