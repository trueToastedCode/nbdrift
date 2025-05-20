"""
ELF INIT_ARRAY Offset Finder

Dieses Programm liest die INIT_ARRAY-Adresse aus einer ELF-Datei aus und 
gibt die entsprechende File-Offset-Adresse (nicht die virtuelle Adresse) 
in die Konsole aus.

Requires: LIEF (Library to Instrument Executable Formats) - pip install lief
"""

import lief
import sys

def virtual_addr_to_file_offset(binary, vaddr):
    """
    Konvertiert eine virtuelle Adresse in einen File-Offset
    
    Args:
        binary: Das LIEF Binary-Objekt
        vaddr: Die virtuelle Adresse (VA)
    
    Returns:
        Der entsprechende File-Offset oder None wenn nicht gefunden
    """
    for segment in binary.segments:
        # Überprüfe, ob die virtuelle Adresse in diesem Segment liegt
        if segment.virtual_address <= vaddr < segment.virtual_address + segment.virtual_size:
            # Berechne den Offset innerhalb des Segments
            offset_in_segment = vaddr - segment.virtual_address
            # Berechne den File-Offset
            return segment.file_offset + offset_in_segment
    
    return None

def find_init_array_file_offset(elf_path):
    """
    Findet den File-Offset der INIT_ARRAY-Sektion in einer ELF-Datei
    
    Args:
        elf_path: Pfad zur ELF-Datei
    
    Returns:
        Tuple (init_array_vaddr, init_array_offset) oder (None, None) wenn nicht gefunden
    """
    try:
        # Parse die ELF-Datei
        binary = lief.parse(elf_path)
        
        # Suche nach dem INIT_ARRAY-Eintrag in den dynamischen Einträgen
        init_array_vaddr = None
        for entry in binary.dynamic_entries:
            if entry.tag == lief.ELF.DynamicEntry.TAG.INIT_ARRAY:
                init_array_vaddr = entry.value
                break
        
        if init_array_vaddr is None:
            print(f"Fehler: Keine INIT_ARRAY-Adresse in {elf_path} gefunden.")
            return None, None
        
        # Konvertiere die virtuelle Adresse in einen File-Offset
        init_array_offset = virtual_addr_to_file_offset(binary, init_array_vaddr)
        
        if init_array_offset is None:
            print(f"Fehler: Konnte die INIT_ARRAY virtuelle Adresse 0x{init_array_vaddr:x} nicht zu einem File-Offset konvertieren.")
            return init_array_vaddr, None
        
        return init_array_vaddr, init_array_offset
    
    except Exception as e:
        print(f"Fehler beim Verarbeiten der ELF-Datei: {e}")
        return None, None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Verwendung: {sys.argv[0]} <elf_datei>")
        sys.exit(1)
    
    elf_path = sys.argv[1]
    init_array_vaddr, init_array_offset = find_init_array_file_offset(elf_path)
    
    if init_array_offset is not None:
        print(f"INIT_ARRAY:")
        print(f"  Virtuelle Adresse: 0x{init_array_vaddr:x}")
        print(f"  File-Offset: 0x{init_array_offset:x}")
    else:
        sys.exit(1)
