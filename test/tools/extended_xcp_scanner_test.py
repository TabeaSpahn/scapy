import threading
import time
import unittest
from subprocess import call
from typing import List

import six

from scapy.config import conf
from scapy.contrib.automotive.xcp.scanner import XCPIdentifierPair, \
    XCPonCANScannerExtended
from scapy.contrib.automotive.xcp.xcp import XCPOnCAN
from scapy.layers.can import CAN
from scapy.main import load_layer, load_contrib

load_layer("can", globals_dict=globals())
load_contrib("automotive.xcp.xcp", globals_dict=globals())
conf.contribs['CAN']['swap-bytes'] = False


class TestExtendendScanner(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.iface = "vcan0"
        self.new_can_socket0 = None
        if 0 != call(["cansend", self.iface, "000#"]):
            # vcan0 is not enabled
            if 0 != call(["sudo", "modprobe", "vcan"]):
                raise Exception("modprobe vcan failed")
            if 0 != call(
                    ["sudo", "ip", "link", "add", "name", self.iface, "type",
                     "vcan"]):
                print("add %s failed: Maybe it was already up?" % self.iface)
            if 0 != call(
                    ["sudo", "ip", "link", "set", "dev", self.iface, "up"]):
                raise Exception("could not bring up %s" % self.iface)

        if 0 != call(["cansend", self.iface, "000#"]):
            raise Exception("cansend doesn't work")

        if six.PY3 and not conf.use_pypy:
            from scapy.contrib.cansocket_native import CANSocket
            self.new_can_socket0 = lambda _: CANSocket(self.iface)

            print("Using Native CANSocket on " + self.iface)
        else:
            from scapy.contrib.cansocket_python_can import CANSocket

            self.new_can_socket0 = lambda _: CANSocket(bustype='socketcan',
                                                       channel=self.iface,
                                                       bitrate=250000,
                                                       timeout=0.01)

            print("Using Soft CANSocket on " + self.iface)

        if self.new_can_socket0 is None:
            from scapy.contrib.cansocket_python_can import CANSocket

            self.new_can_socket = lambda _: CANSocket(bustype='virtual',
                                                      channel=self.iface,
                                                      timeout=0.01)
            print("Using Soft CANSocket on virtual in-process can bus")

        self.request_id = 10
        self.response_id = 11
        self.xcp_identifier_pair = XCPIdentifierPair(
            request_id=self.request_id,
            response_id=self.response_id)

    def setUp(self):
        self.scanner_socket = self.new_can_socket0()
        self.scanner_socket.basecls = XCPOnCAN

        self.ecu_socket = self.new_can_socket0()
        self.ecu_socket.basecls = XCPOnCAN

    def tearDown(self):
        self.scanner_socket.close()
        self.ecu_socket.close()

    def test_extended_scan(self):

        def ecu():
            for _ in range(2):
                pkts = self.ecu_socket.sniff(count=1,
                                             timeout=10)  # type: List[XCPOnCAN]
                if len(pkts) != 1:
                    continue
                pkts[0].show()
                if pkts[0].packet_code == 0xFF:
                    self.ecu_socket.send(CAN(identifier=self.response_id,
                                             data=b'\xFF\x15\xC0\x08\x08\x00\x10\x10'))
            print("## DONE ###")

        thread = threading.Thread(target=ecu)
        thread.start()
        time.sleep(1)
        scanner = XCPonCANScannerExtended(self.scanner_socket,
                                          self.xcp_identifier_pair)
        result = scanner.scan()
        thread.join()
        assert result is not None
        assert "Connect" in result["supported_commands"]
        assert result["Available-Resources"][
                   "calibration_paging"] == "available"
        assert result["Available-Resources"]["daq_list"] == "available"
        assert result["Available-Resources"]["stimulation"] == "not available"
        assert result["Available-Resources"][
                   "flash_programming"] == "available"
        assert result["byte_order"] == "Little Endian"
        assert result["address_granularity"] == 1

        assert result["slave_block_mode"] == "available"
        assert result["max_cto"] == 8
        assert result["max_dto"] == 8
        assert result["xcp_protocol_layer_version"] == 0x10
        assert result["xcp_transport_layer_version"] == 0x10
