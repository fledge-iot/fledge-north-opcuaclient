import os
import asyncio
import time

from datetime import datetime
from asyncua import Client, ua
from asyncua.crypto.security_policies import SecurityPolicyBasic128Rsa15, SecurityPolicyBasic256, \
    SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256RsaOaep
from urllib.parse import urlparse
from typing import Tuple

from fledge.common.common import _FLEDGE_ROOT, _FLEDGE_DATA
from fledge.common import logger

_logger = logger.setup(__name__)


__author__ = "Ashish Jabble"
__copyright__ = "Copyright (c) 2023 Dianomic Systems Inc."
__license__ = "Apache 2.0"
__version__ = "${VERSION}"


class ServerConnectionError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class NodeNotFoundOrAccessDeniedError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class AsyncClient(object):
    """An async client to connect to an OPC-UA server"""
    __slots__ = ['client', 'event_loop', 'name', 'map', 'url', 'user_authentication_mode', 'username', 'password',
                 'security_mode', 'security_policy', 'certs_dir', 'server_certificate', 'client_certificate',
                 'client_private_key', 'client_private_key_passphrase', 'last_error_time', 'error_interval',
                 'attribute_cache']

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
        self.last_error_time = 0
        self.error_interval = 5 * 60  # Set the interval to 5 minutes (300 seconds)
        self.attribute_cache = {}

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
            is_reachable = await self.check_server_reachability()
            if not is_reachable:
                msg = "Server at {} is unreachable".format(self.url)
                raise ServerConnectionError(msg)

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
                if self.client is None:
                    await self.connect()
                if self.client:
                    success, message = await self._write_values_to_nodes(nodes, node_values)
                    _logger.debug("{}-{}".format(success, message))
                    if success:
                        num_sent += len(payloads)
                        is_data_sent = True
                    else:
                        raise NodeNotFoundOrAccessDeniedError(message)
                else:
                    raise Exception
        except asyncio.exceptions.TimeoutError:
            pass
        except ua.uaerrors.UaStatusCodeError as err:
            _logger.error(err, "Data could not be sent as bad status code is encountered.")
        except ServerConnectionError as err:
            current_time = time.time()
            # Suppress errors - if minutes have passed since the last error
            if current_time - self.last_error_time >= self.error_interval:
                _logger.error(err)
                self.last_error_time = current_time
            await self.disconnect()
        except NodeNotFoundOrAccessDeniedError as err:
            current_time = time.time()
            # Suppress errors - if minutes have passed since the last error
            if current_time - self.last_error_time >= self.error_interval:
                _logger.error(err)
                self.last_error_time = current_time
        except Exception as ex:
            current_time = time.time()
            # Suppress errors - if minutes have passed since the last error
            if current_time - self.last_error_time >= self.error_interval:
                _logger.exception(ex, "Failed during write value to OPCUA node.")
                self.last_error_time = current_time
            await self.disconnect()
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

    async def disconnect(self):
        """Close session, secure channel and socket"""
        if self.client is not None:
            await self.client.disconnect()
            self.client = None

    def shutdown(self):
        """Shutdown session"""
        if self.client is not None:
            self.event_loop.run_until_complete(self.disconnect())

    async def validate_node_access(self, nodes: list) -> Tuple[bool, str]:
        """Validates if a node exists and checks its read/write access level.

        Args:
            nodes (list): The NodeIds of the nodes to check (e.g., ['ns=3;i=1010']).

        Returns:
            Tuple[bool, str]: A tuple containing:
                - True if the node exists and has write access, False otherwise.
                - A message providing additional information about the result.
        """
        _logger.debug("attribute_cache: {}".format(self.attribute_cache))
        unique_node_ids = list(set(nodes))
        for node_id in unique_node_ids:
            try:
                if node_id in self.attribute_cache:
                    continue
                node = self.client.get_node(node_id)
                attributes = await node.read_attributes([ua.AttributeIds.NodeId, ua.AttributeIds.AccessLevel])
                if len(attributes) > 1:
                    # Extract the AccessLevel value from the DataValue (it's wrapped in a Variant)
                    access_level_variant = attributes[1].Value
                    access_level_value = access_level_variant.Value
                    if access_level_value is not None:
                        # Determine the access rights based on the bitmask & if the 0x2 flag (CurrentWrite) is set
                        current_write_allowed = (access_level_value & 0x2) > 0
                        if current_write_allowed:
                            self.attribute_cache[node_id] = attributes
                            return True, f"Node with ID {node_id} exists and has write access."
                        else:
                            return False, f"Node with ID {node_id} has read access only."
                    else:
                        raise TypeError
                else:
                    return False, f"Node with ID {node_id} has no valid attributes returned."
            except asyncio.exceptions.TimeoutError:
                if node_id not in self.attribute_cache:
                    return False, f"Timeout error while reading the attribute for node with ID {node_id}."
            except (TypeError, ua.uaerrors._auto.BadNodeIdUnknown):
                return False, f"Node with ID {node_id} does not exist."
            except Exception as ex:
                return False, f"Read attribute of Node with ID {node_id} failed due to error: {ex}"
            finally:
                if node_id in self.attribute_cache:
                    return True, f"Node with ID {node_id} exists and is cached."

    async def check_server_reachability(self) -> bool:
        """Check if the server is reachable
        Returns:
            bool: True if the server is reachable, False otherwise.
        """
        reader, writer = None, None
        try:
            parsed_url = urlparse(self.url)
            # Handle OPC-UA specific URL scheme ('opc.tcp')
            if parsed_url.scheme != 'opc.tcp':
                _logger.error("Unsupported scheme in URL: {}".format(self.url))
                return False
            host = parsed_url.hostname
            port = parsed_url.port
            if not host or not port:
                _logger.error("Invalid URL: {}".format(self.url))
                return False
            # Open the connection explicitly
            reader, writer = await asyncio.open_connection(host, port)
            _logger.debug("Successfully connected to {}".format(self.url))
            return True
        except (OSError, asyncio.TimeoutError) as err:
            _logger.debug("Network error while connecting to {}:{}".format(self.url, str(err)))
            return False
        except Exception as ex:
            _logger.debug("Failed to connect to {} - {}".format(self.url, str(ex)))
            return False
        finally:
            # Ensuring the connection is closed properly, even if there's an error
            if writer and not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            if reader:
                reader.feed_eof()

    async def _write_values_to_nodes(self, nodes, values) -> Tuple[bool, str]:
        """Write values to mulitple nodes in one call"""
        success, message = await self.validate_node_access(nodes)
        if not success:
            return False, message
        node_identifiers = self._convert_node_identifier(nodes)
        _logger.debug("Nodes: {}".format(node_identifiers))
        _logger.debug("Node Values to write: {}".format(values))

        try:
            task = asyncio.create_task(self.client.write_values(node_identifiers, values))
            # TODO: Timeout interval on the basis of payload block size
            # Also asyncua do not allow compression
            await asyncio.wait_for(task, timeout=0.5)
        except Exception:
            # When there is an exception; mostly asyncio timeout error; we need to flush the callback map of UAClient
            self.client.uaclient.protocol._callbackmap.clear()
        return True, "Success"

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

