#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Fabian Wiche <f.wiche@gmx.de>
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>

# This program is published under a GPLv2 license
import getopt
import signal
import sys

from scapy.contrib.automotive.xcp.scanner import XCPOnCANScanner
from scapy.contrib.automotive.xcp.xcp import XCPOnCAN
from scapy.contrib.cansocket import CANSocket
# TOOD: rewrite tests and add documentation

class ScannerParams:
    def __init__(self):
        self.use_extended_can_id = False
        self.broadcast_id = None
        self.broadcast_id_range = None
        self.verbose = False
        self.channel = None


def signal_handler(_sig, _frame):
    print('Interrupting scan!')
    sys.exit(0)


def usage():
    usage_str = """
    Finds XCP slaves using the XCP Broadcast CAN identifier.
    (It is recommended to use this tool with python3)
    required parameters:
        -c, --channel            Linux SocketCAN interface name, e.g.: vcan0
    optional arguments:
        -b, --broadcast_id       XCP Broadcast CAN identifier (in hex)
        -e, --end=END            End XCP Broadcast CAN identifier End ID (in hex)
                                    If actual ID is unknown the scan will test broadcast ids between  --start and --end
        -s, --start=START        Start XCP Broadcast CAN identifier Start ID (in hex)
                                     If actual ID is unknown the scan will test broadcast ids between  --start and --end
        -x, --extended_can_ids  Use extended CAN identifiers
        -v, --verbose           Display information during scan
        -h, --help              Show this

        Examples:
            python3.6 -m scapy.tools.automotive.xcpscanner -c can0
            python3.6 -m scapy.tools.automotive.xcpscanner -c can0 -b 500
            python3.6 -m scapy.tools.automotive.xcpscanner -c can0 -s 50 -e 100
            python3.6 -m scapy.tools.automotive.xcpscanner -c can0 -b 500 -x
    """  # noqa: E501
    print(usage_str)


def init_socket(scan_params: ScannerParams):
    print(f"Initializing socket for {scan_params.channel}")
    try:
        sock = CANSocket(scan_params.channel)
    except Exception as e:
        print(f"\nSocket could not be created: {e}\n")
        sys.exit(1)
    sock.basecls = XCPOnCAN
    return sock


def parse_inputs():
    scanner_params = ScannerParams()
    options = "b:s:e:c:xvh"
    option_strings = ["broadcast_id=", "start=", "end=", "channel=",
                      "extended_can_ids", "verbose", "help"]
    try:
        options = getopt.getopt(sys.argv[1:], options, option_strings)[0]
    except getopt.GetoptError as err:
        print("ERROR:", err)
        usage()
        raise SystemExit
    start = None
    end = None
    for opt, value in options:
        print()
        if opt in ("-h", "--help"):
            usage()
            sys.exit()

        if opt in ("broadcast_id", "-b"):
            scanner_params.broadcast_id = int(value, 16)
        elif opt in ("--start", "-s"):
            start = int(value, 16)
        elif opt in ("--end", "-e"):
            end = int(value, 16)
        elif opt in ("--channel", "-c"):
            scanner_params.channel = value
        elif opt in ("--interface", "-i"):
            scanner_params.interface = value
        elif opt in ("-x", "--extended_can_ids"):
            scanner_params.use_extended_can_id = True
        elif opt in ("--verbose", "-v"):
            scanner_params.verbose = True
        else:
            print("unknown option " + str(opt))
            sys.exit(-1)

    if start is not None and end is not None:
        scanner_params.broadcast_id_range = (start, end)
    elif bool(start) != bool(end):
        print(start)
        print(end)
        print(bool(start))
        print(bool(end))
        print("You can not only set --end/-e or --start/-s."
              "You have ot set both.")
        usage()
        sys.exit()

    return scanner_params


def check_scanner_input(scanner_params: ScannerParams):
    def abort(error):
        print(error)
        usage()
        sys.exit()

    if scanner_params.channel is None:
        abort("Pleas set missing parameter: --channel/-c")

    if scanner_params.broadcast_id_range is not None and \
            scanner_params.broadcast_id_range[0] >= \
            scanner_params.broadcast_id_range[1]:
        abort("Start identifier must be smaller than the end identifier")


def main():
    scanner_params = parse_inputs()
    check_scanner_input(scanner_params)
    can_socket = init_socket(scanner_params)

    try:
        if scanner_params.broadcast_id is not None:
            scanner = XCPOnCANScanner(can_socket,
                                      broadcast_id=scanner_params.broadcast_id,
                                      use_extended_can_id=scanner_params.use_extended_can_id,  # noqa: E501
                                      verbose=scanner_params.verbose)  # noqa: E501

        elif scanner_params.broadcast_id_range is not None:
            scanner = XCPOnCANScanner(can_socket,
                                      broadcast_id_range=scanner_params.broadcast_id_range,  # noqa: E501
                                      use_extended_can_id=scanner_params.use_extended_can_id,  # noqa: E501
                                      verbose=scanner_params.verbose)  # noqa: E501

        else:
            scanner = XCPOnCANScanner(can_socket,
                                      use_extended_can_id=scanner_params.use_extended_can_id,  # noqa: E501
                                      verbose=scanner_params.verbose)  # noqa: E501

        signal.signal(signal.SIGINT, signal_handler)

        results = scanner.start_scan()  # Blocking

        if isinstance(results, list) and len(results) > 0:
            for r in results:
                print(r)
        else:
            print("Detected no XCP slave.")
    except Exception as err:
        print(err, file=sys.stderr)
        sys.exit(1)
    finally:
        can_socket.close()


if __name__ == "__main__":
    main()
