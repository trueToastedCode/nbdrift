#!/usr/bin/env python3
"""
Android Manifest MANAGE_EXTERNAL_STORAGE Permission Modifier

This script adds the MANAGE_EXTERNAL_STORAGE uses-permission to an Android 
manifest file if it's not already present.

Usage:
    python modify_manifest.py <path_to_manifest>
    python modify_manifest.py AndroidManifest.xml
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def add_manage_external_storage_permission(manifest_path):
    """
    Add MANAGE_EXTERNAL_STORAGE permission to Android manifest if not present.
    
    Args:
        manifest_path (str): Path to the AndroidManifest.xml file
        
    Returns:
        bool: True if permission was added, False if already present
    """
    try:
        # Parse the XML file
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Define the permission we're looking for
        target_permission = "android.permission.MANAGE_EXTERNAL_STORAGE"
        
        # Check if permission already exists
        for uses_permission in root.findall('uses-permission'):
            name_attr = uses_permission.get('{http://schemas.android.com/apk/res/android}name')
            if name_attr == target_permission:
                print(f"Permission '{target_permission}' already exists in manifest.")
                return False
        
        # Create new uses-permission element
        new_permission = ET.Element('uses-permission')
        new_permission.set('{http://schemas.android.com/apk/res/android}name', target_permission)
        
        # Find the best insertion point (after other uses-permission elements)
        insertion_index = 0
        for i, child in enumerate(root):
            if child.tag == 'uses-permission':
                insertion_index = i + 1
            elif child.tag == 'application':
                # Insert before application tag if no uses-permission found
                break
        
        # Insert the new permission
        root.insert(insertion_index, new_permission)
        
        # Register namespace to maintain proper formatting
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        
        # Write back to file with proper formatting
        tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
        
        print(f"Added MANAGE_EXTERNAL_STORAGE permission to {manifest_path}")
        return True
        
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        return False
    except FileNotFoundError:
        print(f"Error: File '{manifest_path}' not found.")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False


def main():
    """Main function to handle command line arguments and execute the modification."""
    if len(sys.argv) != 2:
        print("Usage: python modify_manifest.py <path_to_AndroidManifest.xml>")
        print("Example: python modify_manifest.py AndroidManifest.xml")
        sys.exit(1)
    
    manifest_path = sys.argv[1]
    
    # Validate file exists
    if not Path(manifest_path).exists():
        print(f"Error: File '{manifest_path}' does not exist.")
        sys.exit(1)
    
    # Validate it's an XML file
    if not manifest_path.lower().endswith('.xml'):
        print("Warning: File doesn't have .xml extension. Continuing anyway...")
    
    # Create backup
    backup_path = f"{manifest_path}.backup"
    try:
        import shutil
        shutil.copy2(manifest_path, backup_path)
        print(f"Created backup: {backup_path}")
    except Exception as e:
        print(f"Warning: Could not create backup file: {e}")
    
    # Modify the manifest
    success = add_manage_external_storage_permission(manifest_path)
    
    if success:
        print("✓ Manifest successfully modified!")
    else:
        print("✓ No changes needed - permission already present or error occurred.")


if __name__ == "__main__":
    main()
