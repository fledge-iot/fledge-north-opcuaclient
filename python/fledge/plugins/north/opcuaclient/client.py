import os
import asyncio

from datetime import datetime
from asyncua import Client, ua
from asyncua.crypto.security_policies import SecurityPolicyBasic128Rsa15, SecurityPolicyBasic256, \
    SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256RsaOaep

from fledge.common.common import _FLEDGE_ROOT, _FLEDGE_DATA
from fledge.common import logger

_logger = logger.setup(__name__)


__author__ = "Ashish Jabble"
__copyright__ = "Copyright (c) 2023 Dianomic Systems Inc."
__license__ = "Apache 2.0"
__version__ = "${VERSION}"


class AsyncClient(object):
    """An async client to connect to an OPC-UA server."""
    __slots__ = ['client', 'event_loop', 'name', 'map', 'url', 'user_authentication_mode', 'username', 'password',
                 'security_mode', 'security_policy', 'certs_dir', 'server_certificate', 'client_certificate',
                 'client_private_key', 'client_private_key_passphrase']

    def __init__(self, config):
        """
        Args:
            config: Plugin configuration
        Returns:
            None
        """
        self.client = None
        self.event_loop = asyncio.get_event_loop()
        self.name = config["plugin"]["value"]
        self.map = config["map"]["value"]
        self.url = config["url"]["value"]
        self.user_authentication_mode = config["user_authentication_mode"]["value"]
        self.username = config["username"]["value"]
        self.password = config["password"]["value"]
        self.security_mode = config["security_mode"]["value"]
        self.security_policy = config["security_policy"]["value"]
        self.certs_dir = self._get_certs_dir()
        self.server_certificate = config["server_certificate"]["value"]
        self.client_certificate = config["client_certificate"]["value"]
        self.client_private_key = config["client_private_key"]["value"]
        self.client_private_key_passphrase = config["client_private_key_passphrase"]["value"]

    def __repr__(self):
        template = 'Async OPCUA client info <name={opcua.name}, url={opcua.url}, map={opcua.map}, ' \
                   'mode={opcua.user_authentication_mode}, username={opcua.username}, ' \
                   'securityMode={opcua.security_mode}, securityPolicy={opcua.security_policy}, ' \
                   'certsDir={opcua.certs_dir}, serverCert={opcua.server_certificate}, ' \
                   'clientCert={opcua.client_certificate}, clientKey={opcua.client_private_key}>'
        return template.format(opcua=self)

    def __str__(self):
        return self.__repr__()

    async def send_payloads(self, payloads):
        """Send Payloads to the north destination
        Args:
            payloads: A list of payloads
        Returns:
            None
        """
        is_data_sent, last_object_id, num_sent = False, 0, 0
        try:
            _logger.debug('payloads size: {}'.format(len(payloads)))
            nodes = []
            node_values = []
            for p in payloads:
                asset_code = p['asset_code']
                last_object_id = p["id"]
                if asset_code in self.map:
                    for datapoint, item in self.map[asset_code].items():
                        if not (item.get('node') is None) and not (item.get('type') is None):
                            if datapoint in p['reading']:
                                nodes.append(item.get('node'))
                                user_ts = datetime.strptime(p["user_ts"], '%Y-%m-%d %H:%M:%S.%f%z')
                                data_value = ua.DataValue(Value=self._value_to_variant(
                                    p['reading'][datapoint], item.get('type')), SourceTimestamp=user_ts)
                                node_values.append(data_value)
                            else:
                                _logger.debug("{} datapoint is missing in map configuration.".format(datapoint))
                        else:
                            _logger.debug("For {} datapoint, either node or type KV pair is missing "
                                          "in map configuration.".format(datapoint))
                else:
                    _logger.debug("{} asset code is missing in map configuration.".format(asset_code))
            if nodes and node_values:
                await self._write_values_to_nodes(nodes, node_values)
                num_sent += len(payloads)
                is_data_sent = True
        except ua.uaerrors.UaStatusCodeError as err:
            _logger.error(err, "Data could not be sent as bad status code is encountered.")
        except Exception as ex:
            _logger.exception(ex, "Failed during write value to OPCUA node.")
            if self.client:
                await self.client.disconnect()
            self.client = None
        return is_data_sent, last_object_id, num_sent

    async def _create_client_connection(self):
        client = Client(url=self.url)
        plugin_name = "fledge-north-{}".format(self.name)
        client.name = "Python based {}".format(plugin_name)
        client.description = plugin_name
        valid_cert_extensions = ('.der', '.pem')
        if self.user_authentication_mode == "Username And Password":
            client.set_user(self.username)
            client.set_password(self.password)
        if self.security_mode != "None" and self.security_policy != "None":
            server_certificate = None
            certificate = ""
            private_key = ""
            if self.server_certificate:
                if not self.server_certificate.endswith(valid_cert_extensions):
                    _logger.warning("Server certificate must be either in DER or PEM format.")
                else:
                    cert_path = "{}pem/".format(self.certs_dir) if str(self.server_certificate).endswith(
                        '.pem') else self.certs_dir
                    server_certificate = "{}{}".format(cert_path, self.server_certificate)
            if self.client_certificate:
                if not self.client_certificate.endswith(valid_cert_extensions):
                    _logger.warning("Client certificate must be either in DER or PEM format.")
                else:
                    cert_path = "{}pem/".format(self.certs_dir) if str(self.client_certificate).endswith(
                        '.pem') else self.certs_dir
                    certificate = "{}{}".format(cert_path, self.client_certificate)
            else:
                _logger.warning("Client certificate cannot be empty and must be either in DER or PEM format.")
            if self.client_private_key:
                if not str(self.client_private_key).endswith('.pem'):
                    _logger.warning("Private key must be in PEM format.")
                else:
                    private_key = "{}{}".format(self.certs_dir, self.client_private_key)
            else:
                _logger.warning("Private Key cannot be empty and must be in PEM format.")
            passphrase = self.client_private_key_passphrase if self.client_private_key_passphrase else None
            mode, policy = self._get_mode_and_policy()
            _logger.debug(self.__str__())
            # Find Application URI as it requires to match the URI in the certificate
            servers = await client.connect_and_find_servers()
            # _logger.debug("Servers list: {}".format(servers))
            app_uri = [s.ApplicationUri for s in servers]
            _logger.debug("Application URI: {}".format(app_uri[0]))
            client.application_uri = app_uri[0]
            await client.set_security(policy=policy, certificate=certificate, private_key=private_key,
                                      private_key_password=passphrase, server_certificate=server_certificate,
                                      mode=mode)
        return client

    def _convert_node_identifier(self, nodes):
        return [self.client.get_node(n) for n in nodes]

    async def connect(self):
        """Connect, create and activate session"""
        self.client = await self._create_client_connection()
        await self.client.connect()

    def disconnect(self):
        """Close session, secure channel and socket"""
        if self.client is not None:
            self.event_loop.run_until_complete(self.client.disconnect())

    async def _write_values_to_nodes(self, nodes, values):
        """Write values to mulitple nodes in one call"""
        if self.client is None:
            await self.connect()
        node_identifiers = self._convert_node_identifier(nodes)
        _logger.debug("Nodes: {}".format(node_identifiers))
        _logger.debug("Node Values to write: {}".format(values))

        try:
            task = asyncio.create_task(self.client.write_values(node_identifiers, values))
            # TODO: Timeout interval on the basis of payload block size
            # Also asyncua do not allow compression
            await asyncio.wait_for(task, timeout=0.5)
            # asyncio.ensure_future(self.client.write_values(node_identifiers, values))
        except Exception:
            # When there is an exception; mostly asyncio timeout error; we need to flush the callback map of UAClient
            self.client.uaclient.protocol._callbackmap.clear()

    def _value_to_variant(self, value, type_):
        type_ = type_.strip().lower()
        if type_ in ("bool", "boolean"):
            return self._value_to_variant_type(value, self._convert_to_bool, ua.VariantType.Boolean)
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

    def _value_to_variant_type(self, value, ptype, variant_type=None):
        value = [ptype(i) for i in value] if isinstance(value, list) else ptype(value)
        return ua.Variant(value, variant_type) if variant_type else ua.Variant(value)

    def _convert_to_bool(self, value):
        if value in (True, "True", "true", "On", "on", 1, "1"):
            return True
        if value in (False, "False", "false", "Off", "off", 0, "0"):
            return False
        return bool(value)

    def _get_certs_dir(self, _path="/etc/certs/"):
        dir_path = _FLEDGE_DATA + _path if _FLEDGE_DATA else _FLEDGE_ROOT + '/data' + _path
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        return os.path.expanduser(dir_path)

    def _get_mode_and_policy(self):
        # Note: Basic256, Basic128Rsa15 are DEPRECATED! Avoid to use though their support is still available
        if self.security_policy == "Basic256Sha256":
            policy = SecurityPolicyBasic256Sha256
        elif self.security_policy == "Aes128Sha256RsaOaep":
            policy = SecurityPolicyAes128Sha256RsaOaep
        elif self.security_policy == "Basic128Rsa15":
            policy = SecurityPolicyBasic128Rsa15
        else:
            # Basic256
            policy = SecurityPolicyBasic256
        mode = ua.MessageSecurityMode.Sign if self.security_mode == "Sign" else ua.MessageSecurityMode.SignAndEncrypt
        return mode, policy

