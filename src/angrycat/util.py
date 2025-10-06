from datetime import datetime
from pathlib import Path
from typing import Dict


def generate_temp_filename(fields: Dict[str, str], base_dir: str) -> str:
    """
    Generate a unique temporary filename in a subfolder of /tmp.

    Filename format:
        <field1>_<value1>_<field2>_<value2>_..._<datetime>_<counter>.tmp

    If more than 50 files exist in the folder, remove the oldest 5.
    """
    folder = Path(base_dir)
    folder.mkdir(parents=True, exist_ok=True)

    # Cleanup if too many files
    all_files = sorted(folder.glob("*"), key=lambda f: f.stat().st_mtime)
    if len(all_files) > 50:
        for old in all_files[:5]:
            try:
                old.unlink()
            except Exception as e:
                print(f"Warning: could not remove {old}: {e}")

    # Timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Build field string like: cpu_x86_slot_3
    field_str = "_".join(f"{k}_{v}" for k, v in fields.items())

    # Find a unique counter
    counter = 0
    while True:
        filename = f"{field_str}_{timestamp}_{counter}.tmp"
        filepath = folder / filename
        if not filepath.exists():
            break
        counter += 1

    return str(filepath)

def hexdump(data: bytes, start_address: int = 0) -> None:
    """
    Pretty-print a bytes object in hex-editor style, 32 bytes per line,
    with an extra separator every 8 bytes in the hex column.

    Parameters:
    -----------
    data : bytes
        The data to dump.
    start_address : int, optional
        The address to display at the beginning of the first line (default is 0).
    """
    width = 32
    group_size = 8
    # Calculate total hex-column width:
    #   each byte = 2 hex chars
    #   between bytes = 1 space  → (width - 1) spaces
    #   plus (width//group_size - 1) extra spaces to separate groups
    hex_col_width = width * 2 + (width - 1) + (width // group_size - 1)

    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]

        # build a list of two-char hex strings
        hex_bytes = [f"{b:02X}" for b in chunk]
        # group into sublists of length `group_size`
        groups = [
            hex_bytes[i : i + group_size]
            for i in range(0, len(hex_bytes), group_size)
        ]
        # join bytes in each group with single spaces, then join groups with double spaces
        hex_col = "  ".join(" ".join(g) for g in groups)
        hex_col = hex_col.ljust(hex_col_width)

    # ASCII representation: printable 32-126, else dot
        ascii_col = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)

        print(f"{start_address + offset:08X}  {hex_col}  {ascii_col}")
