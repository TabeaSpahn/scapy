# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = XCPScanner
# scapy.contrib.status = loads
from collections import namedtuple
from typing import Optional, List, Type, Iterable, Dict, Union

from scapy.contrib.automotive.xcp.cto_commands_master import \
    TransportLayerCmd, TransportLayerCmdGetSlaveId, Connect, Disconnect, \
    GetStatus, GetCommModeInfo, GetId
from scapy.contrib.automotive.xcp.cto_commands_slave import \
    ConnectPositiveResponse, TransportLayerCmdGetSlaveIdResponse, \
    CommonModeInfoPositiveResponse, StatusPositiveResponse, \
    IdPositiveResponse, GenericResponse
from scapy.contrib.automotive.xcp.xcp import CTORequest, XCPOnCAN
from scapy.contrib.cansocket_native import CANSocket
from scapy.packet import Packet

XCPIdentifierPair = namedtuple('XCPIdentifierPair', 'request_id response_id')


# TODO: include in actual scanner
class XCPonCANScannerExtended:
    """
    Scans for supported commands
    """

    def __init__(self, can_socket, xcp_identifier_pair,
                 sniff_time=0.5, verbose=False):
        # type: (CANSocket, XCPIdentifierPair, Optional[float], Optional[bool]) -> None # noqa: E501

        self.__socket = can_socket
        self.xcp_identifier_pair = xcp_identifier_pair
        self.__flags = 0
        self.__sniff_time = sniff_time
        self.__verbose = verbose

        self.result = {
            "supported_commands": []}  # type: Dict[str, Union[str, List, dict]] # noqa: E501

    def _send_and_filter_reply(self, cto_body, answer_type):
        # type: (CTORequest, Type) -> Optional[Packet]

        cto_request = XCPOnCAN(identifier=self.xcp_identifier_pair.request_id,
                               flags=self.__flags) \
                      / CTORequest() / cto_body
        response = self.__socket \
            .sr1(cto_request,
                 timeout=self.__sniff_time,
                 verbose=self.__verbose)
        if response is None or response.identifier != self.xcp_identifier_pair.response_id:
            return
        return response[answer_type] if response.haslayer(
            answer_type) else None

    def _add_connect_info_to_result(self, connect_positive_response):
        # type: (ConnectPositiveResponse) -> None
        self.result["supported_commands"].append("Connect")

        self.result["Available-Resources"] = {
            "calibration_paging":
                "available" if "cal_pag" in connect_positive_response.resource
                else "not available",
            "daq_list":
                "available" if "daq" in connect_positive_response.resource
                else "not available",
            "stimulation":
                "available" if "stim" in connect_positive_response.resource
                else "not available",
            "flash_programming":
                "available" if "pgm" in connect_positive_response.resource
                else "not available",
        }

        self.result["byte_order"] = "Big Endian" if \
            int(connect_positive_response.comm_mode_basic.byte_order) == 1 \
            else "Little Endian"
        self.result["address_granularity"] = \
            connect_positive_response.get_address_granularity()

        self.result["slave_block_mode"] = \
            "available" if "slave_block_mode" \
                           in connect_positive_response.comm_mode_basic \
            else "not available"
        self.result["max_cto"] = connect_positive_response.max_cto

        if connect_positive_response.comm_mode_basic.byte_order:
            self.result["max_dto"] = connect_positive_response.max_dto
        else:
            self.result["max_dto"] = connect_positive_response.max_dto_le

        self.result["xcp_protocol_layer_version"] = \
            connect_positive_response.xcp_protocol_layer_version_number_msb
        self.result["xcp_transport_layer_version"] = \
            connect_positive_response.xcp_transport_layer_version_number_msb

    def _add_comm_mode_info_to_result(self, comm_mode_info_response):
        # type: (CommonModeInfoPositiveResponse) -> None
        self.result["supported_commands"].append("GetCommModeInfo")

        # high nibble
        version_number = comm_mode_info_response.xcp_driver_version_number[:1]
        # low nibble
        minor_version = comm_mode_info_response.xcp_driver_version_number[1:2]
        self.result[
            "xcp_driver_version"] = version_number + "." + minor_version

        if "master_block_mode" in comm_mode_info_response:
            self.result["master_block_mode"] = {
                "max_consecutive_packets": comm_mode_info_response.max_bs,
                "min_separation_time_in_ms":
                    comm_mode_info_response.min_st * 10,
            }
        else:
            self.result["master_block_mode"] = "Not available"

        if "interleaved_mode" in comm_mode_info_response:
            self.result["interleaved_mode"] = {
                "max_consecutive_command_packets":
                    comm_mode_info_response.queue_size
            }
        else:
            self.result["interleaved_mode"] = "Not available"

    def _add_status_info_to_result(self, status_response):
        # type: (StatusPositiveResponse) -> None
        self.result["supported_commands"].append("GetStatus")

        session_status = status_response.current_session_status
        self.result["current_session_status"] = {
            "store_cal_req":
                'set' if 'store_cal_req' in session_status else 'unset',
            "store_daq_req":
                'set' if 'store_daq_req' in session_status else 'unset',
            "clear_daq_request":
                'set' if 'clear_daq_request' in session_status else 'unset',
            "rdata_transfer":
                'not running' if 'daq_running' in session_status
                else 'running',
            "resume_mode":
                'active' if 'resume' in session_status else 'not active'
        }
        resource = status_response.resource
        self.result["current_resource_protection_status"] = {
            "calibration_paging":
                "protected" if "cal_pag" in resource else "unprotected",
            "daq_list": "protected" if "daq" in resource else "unprotected",
            "stimulation":
                "protected" if "stim" in resource else "unprotected",
            "flash_programming":
                "protected" if "pgm" in resource else "not available",
        }

    def _add_id_info_to_result(self, id_response, mode):
        # type: (IdPositiveResponse, int) -> None
        if id_response.mode == 1:
            self.result[
                "a2l_mode_" + str(mode)] = id_response.element.decode(
                "ascii") if id_response.length > 0 else "unsupported mode"
        else:
            self.result[
                "a2l_mode_" + str(mode)] = "Must be read with UPLOAD"

    # TODO: only conect is tested -> test other packets
    # Idea: scan not only for information, but test which functions are open
    def scan(self):
        # standard commands (unprotected)
        connect_request = Connect(connection_mode=0x00)

        connect_response = self._send_and_filter_reply(connect_request,
                                                       ConnectPositiveResponse)
        if connect_response is None:
            print(
                "Could not connect to XCP client with identifier_pair: " +
                str(self.xcp_identifier_pair))
            return
        self._add_connect_info_to_result(connect_response)

        if "optional" in connect_response.resource:
            get_comm_mode_info_request = GetCommModeInfo()
            comm_mode_info_response = self._send_and_filter_reply(
                get_comm_mode_info_request,
                CommonModeInfoPositiveResponse)
            if comm_mode_info_response is not None:
                self._add_comm_mode_info_to_result(comm_mode_info_response)

        status_response = self._send_and_filter_reply(GetStatus(),
                                                      StatusPositiveResponse)

        if status_response is not None:
            self._add_status_info_to_result(status_response)

        for mode in range(0, 5):
            get_id_request = GetId(identification_type=0x00)
            id_response = self._send_and_filter_reply(get_id_request,
                                                      IdPositiveResponse)
            if id_response is None:
                continue
            self._add_id_info_to_result(id_response, mode)

        # end -> disconnect
        _ = self._send_and_filter_reply(Disconnect(), GenericResponse)

        return self.result


class XCPOnCANScanner:
    """
    Scans for XCP Slave on CAN
    """

    def __init__(self, can_socket, id_range=None,
                 sniff_time=0.1, verbose=False):
        # type: (CANSocket, Optional[Iterable[int]], Optional[float], Optional[bool]) -> None # noqa: E501

        """
        Constructor
        :param can_socket: Can Socket with XCPonCAN as basecls for scan
        :param id_range: CAN id range to scan
        :param sniff_time: time the scan waits for a response
                           after sending a request
        """
        self.__socket = can_socket
        self.id_range = id_range or range(0, 0x800)
        self.__flags = 0
        self.__sniff_time = sniff_time
        self.__verbose = verbose

    def _scan(self, identifier, body, answer_type):
        # type: (int, CTORequest, Type) -> List # noqa: E501

        self.log_verbose("Scan for id: " + str(identifier))
        cto_request = \
            XCPOnCAN(identifier=identifier, flags=self.__flags) \
            / CTORequest() / body

        req_and_res_list, _unanswered = \
            self.__socket.sr(cto_request, timeout=self.__sniff_time,
                             verbose=self.__verbose, multi=True)

        if len(req_and_res_list) == 0:
            self.log_verbose(
                "No answer for identifier: " + str(identifier))
            return []

        valid_req_and_res_list = filter(
            lambda req_and_res: req_and_res[1].haslayer(answer_type),
            req_and_res_list)
        return list(valid_req_and_res_list)

    def _send_connect(self, identifier):
        # type: (int) -> List[XCPIdentifierPair]
        """
        Sends CONNECT Message on the Control Area Network
        """
        all_slaves = []
        body = Connect()
        xcp_req_and_res_list = self._scan(identifier, body,
                                          ConnectPositiveResponse)

        for req_and_res in xcp_req_and_res_list:
            result = XCPIdentifierPair(response_id=req_and_res[1].identifier,
                                       request_id=identifier)
            all_slaves.append(result)
            self.log_verbose(
                "Detected XCP slave for broadcast identifier: " + str(
                    identifier) + "\nResponse: " + str(result))

        if len(all_slaves) == 0:
            self.log_verbose(
                "No XCP slave detected for identifier: " + str(identifier))
        return all_slaves

    def _send_get_slave_id(self, identifier):
        # type: (int) -> List[XCPIdentifierPair]
        """
        Sends GET_SLAVE_ID message on the Control Area Network
        """
        all_slaves = []
        body = TransportLayerCmd() / TransportLayerCmdGetSlaveId()
        xcp_req_and_res_list = \
            self._scan(identifier, body, TransportLayerCmdGetSlaveIdResponse)

        for req_and_res in xcp_req_and_res_list:
            response = req_and_res[1]
            # The protocol will also mark other XCP messages that might be
            # send as TransportLayerCmdGetSlaveIdResponse
            # -> Payload must be checked. It must include XCP
            if response.position_1 != 0x58 or response.position_2 != 0x43 or \
                    response.position_3 != 0x50:
                continue

            # Identifier that the master must use to send packets to the slave
            # and the slave will answer with
            request_id = \
                response["TransportLayerCmdGetSlaveIdResponse"].can_identifier

            result = XCPIdentifierPair(request_id=request_id,
                                       response_id=response.identifier)
            all_slaves.append(result)
            self.log_verbose(
                "Detected XCP slave for broadcast identifier: " + str(
                    identifier) + "\nResponse: " + str(result))

        return all_slaves

    def scan_with_get_slave_id(self):
        # type: () -> List[XCPIdentifierPair]
        """Starts the scan for XCP devices on CAN with the transport specific
        GetSlaveId Message"""
        self.log_verbose("Start scan with GetSlaveId id in range: " + str(
            self.id_range))

        for identifier in self.id_range:
            ids = self._send_get_slave_id(identifier)
            if len(ids) > 0:
                return ids

        return []

    def scan_with_connect(self):
        # type: () -> List[XCPIdentifierPair]
        self.log_verbose("Start scan with CONNECT id in range: " + str(
            self.id_range))
        results = []
        for identifier in self.id_range:
            result = self._send_connect(identifier)
            if len(result) > 0:
                results.extend(result)
        return results

    def log_verbose(self, output):
        if self.__verbose:
            print(output)
