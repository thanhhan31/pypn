# -*- coding: utf-8 -*-
"""
Small Socks5 Proxy Server in Python
from https://github.com/MisterDaneel/
Optimized for Python 3.12 with best practices.
"""

# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9050
OUTGOING_INTERFACE = ""

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'

class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit: bool = False

    def set_status(self, status: bool) -> None:
        """ set exist status """
        self.exit = status

    def get_status(self) -> bool:
        """ get exit status """
        return self.exit

def error(msg: str = "", err: Optional[tuple] = None) -> None:
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print(f"{msg} - Code: {err[0] if err else ''}, Message: {err[1] if err else ''}")
    else:
        traceback.print_exc()

def proxy_loop(socket_src: socket.socket, socket_dst: socket.socket) -> None:
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return

def connect_to_dst(dst_addr: str, dst_port: int) -> Optional[socket.socket]:
    """ Connect to desired destination """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print("Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
            return None
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return None

def request_client(wrapper: socket.socket) -> tuple[bool, bytes, Optional[str], Optional[int]]:
    """ Client request details """
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        return False, b'\x01', None, None
    if len(s5_request) < 4:
        return False, b'\x01', None, None
    if s5_request[0:1] != VER:
        return False, b'\x01', None, None
    if s5_request[1:2] != CMD_CONNECT:
        return False, b'\x07', None, None
    if s5_request[2:3] != b'\x00':
        return False, b'\x01', None, None
    atyp = s5_request[3:4]
    if atyp == ATYP_IPV4:
        if len(s5_request) < 10:
            return False, b'\x01', None, None
        dst_addr = socket.inet_ntoa(s5_request[4:8])
        dst_port = unpack('>H', s5_request[8:10])[0]
    elif atyp == ATYP_DOMAINNAME:
        if len(s5_request) < 5:
            return False, b'\x01', None, None
        sz_domain_name = s5_request[4]
        if len(s5_request) < 7 + sz_domain_name:
            return False, b'\x01', None, None
        dst_addr_bytes = s5_request[5:5 + sz_domain_name]
        try:
            dst_addr = dst_addr_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return False, b'\x01', None, None
        dst_port = unpack('>H', s5_request[5 + sz_domain_name:7 + sz_domain_name])[0]
    else:
        return False, b'\x08', None, None
    return True, b'\x00', dst_addr, dst_port

def request(wrapper: socket.socket) -> None:
    success, rep, dst_addr, dst_port = request_client(wrapper)
    if not success:
        bnd = b'\x00' * 6
    else:
        socket_dst = connect_to_dst(dst_addr, dst_port)
        if socket_dst is None:
            rep = b'\x05'  # connection refused
            bnd = b'\x00' * 6
        else:
            local_addr = socket_dst.getsockname()
            bnd = socket.inet_aton(local_addr[0]) + pack(">H", local_addr[1])
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        pass
    if success and rep == b'\x00':
        proxy_loop(wrapper, socket_dst)
    wrapper.close()
    if 'socket_dst' in locals() and socket_dst is not None:
        socket_dst.close()

def subnegotiation_client(wrapper: socket.socket) -> bytes:
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        return M_NOTAVAILABLE
    if len(identification_packet) < 2:
        return M_NOTAVAILABLE
    if identification_packet[0:1] != VER:
        return M_NOTAVAILABLE
    nmethods = identification_packet[1]
    if len(identification_packet) != 2 + nmethods:
        return M_NOTAVAILABLE
    methods = identification_packet[2:2 + nmethods]
    for method in methods:
        if method == ord(M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE

def subnegotiation(wrapper: socket.socket) -> bool:
    method = subnegotiation_client(wrapper)
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        return False
    return True

def connection(wrapper: socket.socket) -> None:
    """ Function run by a thread """
    if subnegotiation(wrapper):
        request(wrapper)

def create_socket() -> socket.socket:
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(1)
    return sock

def bind_port(sock: socket.socket) -> None:
    """
    Bind the socket to address and
    listen for connections made to the socket
    """
    try:
        print(f'Bind {LOCAL_PORT}')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(1)
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(1)

def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)

def main():
    """ Main function """
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        while not EXIT.get_status():
            try:
                wrapper, _ = new_socket.accept()
                wrapper.setblocking(1)
                executor.submit(connection, wrapper)
            except socket.timeout:
                continue
            except socket.error as err:
                error("Accept failed", err)
                continue
            except TypeError as err:
                error("TypeError in accept", err)
                sys.exit(1)
    new_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A simple Socks5 proxy server.')
    parser.add_argument('--port', type=int, default=9050, help='Port to listen on (1-65535)')
    parser.add_argument('--addr', type=str, default='0.0.0.0', help='Address to bind to')
    parser.add_argument('--interface', type=str, default='', help='Outgoing network interface')
    args = parser.parse_args()
    LOCAL_PORT = args.port
    LOCAL_ADDR = args.addr
    OUTGOING_INTERFACE = args.interface
    EXIT = ExitStatus()
    main()