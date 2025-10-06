#!/usr/bin/env python3
import argparse
import socket
import logging

from angrycat.protocol import (
    Packet,
    PagingInfoPacket,
    GetPagingInfoPacket,
)

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Sentinel values
CURRENT_TABLE  = 0xFFFF  # dump entire table at a given level
PREVIOUS_ENTRY = 0xFFFE  # request specific entry in prefix

# IA-32e page sizes by level
PAGE_SIZES = {
    1: 4096,
    2: 2 * 1024 * 1024,
    3: 1024 * 1024 * 1024,
    4: None,  # PML4 doesn't map pages directly
}


def get_paging_packets(core: int, indices: list[int], host: str, port: int):
    """
    Send GETPAGINGINFO(core, indices) and return all PagingInfoPacket responses.
    """
    pkt = GetPagingInfoPacket(core=core, indices=indices)
    logging.debug(f"Sent GETPAGINGINFO packet: {pkt}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        data = pkt.pack()
        sock.sendall(data)
        responses = Packet.read_messages(sock)

    results = []
    for resp in responses:
        logging.debug(f"Received packet: {resp}")
        if isinstance(resp, PagingInfoPacket):
            for entry in resp.entries:
                print(entry)
            results.append(resp)
    return results


def va_to_indices(va: int):
    """
    Convert VA to paging indices and page offset.
    """
    shifts = [39, 30, 21, 12]
    indices = [(va >> s) & 0x1FF for s in shifts]
    offset = va & 0xFFF
    return indices, offset


def parse_path(path_str: str):
    """
    Parse a comma-separated path. Interpret as:
      - 'all' at end: dump entire table at that level
      - fewer than 4 indices without 'all': previous-entry mode
      - exactly 4 indices: exact entry mode
    Returns dict with 'mode' in {'level','prev','exact'} and relevant data.
    """
    parts = [p.strip().lower() for p in path_str.split(',') if p.strip()]
    if parts[-1] == 'all':
        prefix = [int(p, 0) for p in parts[:-1]]
        return {'mode': 'level', 'prefix': prefix}
    if len(parts) < 4:
        prefix = [int(p, 0) for p in parts]
        return {'mode': 'prev', 'prefix': prefix}
    # exact mode
    idxs = [int(p, 0) for p in parts[:4]]
    return {'mode': 'exact', 'indices': idxs}


def build_prev_indices(prefix: list[int]) -> list[int]:
    """
    Build indices list using PREVIOUS_ENTRY after prefix.
    """
    indices = prefix + [PREVIOUS_ENTRY] + [0] * (4 - len(prefix) - 1)
    return indices


def build_level_indices(prefix: list[int]) -> list[int]:
    """
    Build indices list using CURRENT_TABLE after prefix.
    """
    indices = prefix + [CURRENT_TABLE] + [0] * (4 - len(prefix) - 1)
    return indices


def main():
    parser = argparse.ArgumentParser(description="Query paging via GETPAGINGINFO")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3239)
    parser.add_argument("--core", type=int, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--path", help="Path e.g. all | 0,all | 0,0,all | 0,0,0,all | 1,2,3,4 | 0 | 0,0")
    group.add_argument("--translate", type=lambda x: int(x, 0), help="Translate VA to PA")
    group.add_argument("--dump-all", action="store_true", help="Dump full paging tree")
    parser.add_argument("--show-empty", action="store_true", help="Show non-present entries")
    args = parser.parse_args()

    host, port, core = args.host, args.port, args.core

    if args.path:
        info = parse_path(args.path)
        mode = info['mode']
        if mode == 'exact':
            idxs = info['indices']
            logging.debug(f"Exact entry indices: {idxs}")
            get_paging_packets(core, idxs, host, port)
        elif mode == 'prev':
            prefix = info['prefix']
            logging.debug(f"Previous-entry prefix: {prefix}")
            indices = build_prev_indices(prefix)
            get_paging_packets(core, indices, host, port)
        else:  # level
            prefix = info['prefix']
            logging.debug(f"Level-dump prefix: {prefix}")
            indices = build_level_indices(prefix)
            get_paging_packets(core, indices, host, port)

    elif args.translate is not None:
        va = args.translate
        logging.debug(f"Translating VA: 0x{va:X}")
        idxs, offset = va_to_indices(va)
        logging.debug(f"Indices: {idxs}, offset: {offset}")
        get_paging_packets(core, idxs, host, port)

    elif args.dump_all:
        logging.debug("Dump-all: recursively walking full tree")
        # start at PML4 level full table
        indices = [CURRENT_TABLE] + [0]*3
        responses = get_paging_packets(core, indices, host, port)
        # This only prints entries; full recursion could be added

if __name__ == "__main__":
    main()
