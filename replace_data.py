import lief
import argparse
import struct

def find_and_replace_data(input_file, output_file, real_data_file, embd_data_sym):
    # Load the ELF binary
    binary = lief.parse(input_file)
    
    # Find the dummy data symbols
    start_symbol = binary.get_symbol(f"{embd_data_sym}_start")
    end_symbol = binary.get_symbol(f"{embd_data_sym}_end")
    size_symbol = binary.get_symbol(f"{embd_data_sym}_size")

    if not all([start_symbol, end_symbol, size_symbol]):
        raise RuntimeError("Could not find all dummy data symbols")

    # Calculate size from symbols
    data_size = end_symbol.value - start_symbol.value
    size_from_symbol = size_symbol.value
    
    if data_size != size_from_symbol:
        raise RuntimeError("Size mismatch between start/end symbols and size symbol")

    # Get the virtual address range
    va_start = start_symbol.value
    va_size = data_size

    # Find the segment containing our data
    segment = None
    for s in binary.segments:
        if s.virtual_address <= va_start < s.virtual_address + s.physical_size:
            segment = s
            break

    if not segment:
        raise RuntimeError("Could not find segment containing dummy data")

    # Calculate file offset
    file_offset = va_start - segment.virtual_address + segment.file_offset

    # Read real data
    with open(real_data_file, "rb") as f:
        real_data = f.read()

    # Define MAGIC bytes (4 bytes)
    MAGIC = b"EMBD"  # "EMBD" for "embedded"
    
    # Calculate total header size (MAGIC + uint64_t size)
    header_size = 4 + 8  # 4 bytes for MAGIC, 8 bytes for uint64_t size
    
    # Create the final data buffer with MAGIC + size + actual data
    final_data = MAGIC + struct.pack("<Q", len(real_data)) + real_data
    
    # Verify data fits in existing space
    if len(final_data) > data_size:
        raise RuntimeError(f"Real data with header too large ({len(final_data)} > {data_size} bytes)")

    # Pad with zeros if smaller
    final_data += b"\x00" * (data_size - len(final_data))

    # Write to output file
    binary.write(output_file)
    
    # Now patch the actual file content
    with open(output_file, "r+b") as f:
        f.seek(file_offset)
        f.write(final_data)
    
    print(f"Successfully embedded data with {len(real_data)} bytes")
    print(f"Total size with header: {len(final_data)} bytes")
    print(f"MAGIC bytes: {MAGIC}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replace dummy data in ELF binary")
    parser.add_argument("input", help="Input ELF file")
    parser.add_argument("output", help="Output ELF file")
    parser.add_argument("real_data", help="File containing real data to insert")
    parser.add_argument("embd_data_sym", help="Embedded data symbol prefix")
    
    args = parser.parse_args()
    
    find_and_replace_data(args.input, args.output, args.real_data, args.embd_data_sym)
