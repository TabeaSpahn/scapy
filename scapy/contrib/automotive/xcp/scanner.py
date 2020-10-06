# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = XCPScanner
# scapy.contrib.status = loads

from typing import Optional, List, Tuple

from scapy.contrib.automotive.xcp.cto_commands_master import \
    TransportLayerCmd, TransportLayerCmdGetSlaveId, Connect
from scapy.contrib.automotive.xcp.xcp import CTORequest, XCPOnCAN
from scapy.contrib.cansocket_native import CANSocket


class XCPScannerResult:
    def __init__(self, slave_id, response_id):
        self.slave_id = slave_id
        self.response_id = response_id


class XCPOnCANScanner:
    """
    Scans for XCP Slave on CAN
    """

    def __init__(self, can_socket, id_range=None,
                 sniff_time=0.1, verbose=False):
        # type: (CANSocket, Optional[Tuple[int, int]], Optional[float], Optional[bool]) -> None # noqa: E501

        """
        Constructor
        :param can_socket: Can Socket with XCPonCAN as basecls for scan
        :param id_range: CAN id range to scan
        :param sniff_time: time the scan waits for a response
                           after sending a request
        """
        self.__socket = can_socket
        self.id_range = id_range or (0, 0x7ff)
        self.__flags = 0
        self.__sniff_time = sniff_time
        self.__verbose = verbose

    def _scan(self, identifier, body, answer_type):
        # type: (int, CTORequest, str) -> List # noqa: E501

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
            lambda req_and_res: answer_type in req_and_res[1],
            req_and_res_list)
        return list(valid_req_and_res_list)

    def _send_connect(self, identifier):
        # type: (int) -> List[XCPScannerResult]
        """
        Sends CONNECT Message on the Control Area Network
        """
        all_slaves = []
        body = Connect()
        xcp_req_and_res_list = self._scan(identifier, body,
                                          "ConnectPositiveResponse")

        for req_and_res in xcp_req_and_res_list:
            result = XCPScannerResult(response_id=req_and_res[1].identifier,
                                      slave_id=identifier)
            all_slaves.append(result)
            self.log_verbose(
                "Detected XCP slave for broadcast identifier: " + str(
                    identifier) + "\nResponse: " + str(result))

        if len(all_slaves) == 0:
            self.log_verbose(
                "No XCP slave detected for identifier: " + str(identifier))
        return all_slaves

    def _send_get_slave_id(self, identifier):
        # type: (int) -> List[XCPScannerResult]
        """
        Sends GET_SLAVE_ID message on the Control Area Network
        """
        all_slaves = []
        body = TransportLayerCmd() / TransportLayerCmdGetSlaveId()
        xcp_req_and_res_list = \
            self._scan(identifier, body, "TransportLayerCmdGetSlaveIdResponse")

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
            slave_id = \
                response["TransportLayerCmdGetSlaveIdResponse"].can_identifier

            result = XCPScannerResult(slave_id, response.identifier)
            all_slaves.append(result)
            self.log_verbose(
                "Detected XCP slave for broadcast identifier: " + str(
                    identifier) + "\nResponse: " + str(result))

        return all_slaves

    def scan_with_get_slave_id(self):
        # type: () -> List[XCPScannerResult]
        """Starts the scan for XCP devices on CAN with the transport specific
        GetSlaveId Message"""
        self.log_verbose("Start scan with GetSlaveId id in range: " + str(
            self.id_range))

        for identifier in range(self.id_range[0], self.id_range[1] + 1):
            ids = self._send_get_slave_id(identifier)
            if len(ids) > 0:
                return ids

        return []

    def scan_with_connect(self):
        # type: () -> List[XCPScannerResult]
        self.log_verbose("Start scan with CONNECT id in range: " + str(
            self.id_range))
        results = []
        for identifier in range(self.id_range[0], self.id_range[1] + 1):
            result = self._send_connect(identifier)
            if len(result) > 0:
                results.extend(result)
        return results

    def log_verbose(self, output):
        if self.__verbose:
            print(output)
