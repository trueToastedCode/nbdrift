#!/usr/bin/env python3
"""
Android Manifest External Storage Permissions Modifier

This script adds all necessary external storage permissions to an Android 
manifest file if they're not already present:
- READ_EXTERNAL_STORAGE
- WRITE_EXTERNAL_STORAGE  
- MANAGE_EXTERNAL_STORAGE

Usage:
    python modify_manifest.py <path_to_manifest>
    python modify_manifest.py AndroidManifest.xml
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def add_external_storage_permissions(manifest_path):
    """
    Add all external storage permissions to Android manifest if not present.
    
    Args:
        manifest_path (str): Path to the AndroidManifest.xml file
        
    Returns:
        dict: Summary of permissions added/already present
    """
    try:
        # Parse the XML file
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Define the permissions we need
        required_permissions = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE", 
            "android.permission.MANAGE_EXTERNAL_STORAGE"
        ]
        
        # Check which permissions already exist
        existing_permissions = set()
        for uses_permission in root.findall('uses-permission'):
            name_attr = uses_permission.get('{http://schemas.android.com/apk/res/android}name')
            if name_attr in required_permissions:
                existing_permissions.add(name_attr)
        
        # Determine which permissions need to be added
        permissions_to_add = [perm for perm in required_permissions if perm not in existing_permissions]
        
        result = {
            'added': [],
            'already_present': list(existing_permissions),
            'total_added': 0
        }
        
        if not permissions_to_add:
            print("All external storage permissions already exist in manifest.")
            result['total_added'] = 0
            return result
        
        # Find the best insertion point (after other uses-permission elements)
        insertion_index = 0
        for i, child in enumerate(root):
            if child.tag == 'uses-permission':
                insertion_index = i + 1
            elif child.tag == 'application':
                # Insert before application tag if we've moved past uses-permission elements
                break
        
        # Add missing permissions in the specified order
        for permission in permissions_to_add:
            new_permission = ET.Element('uses-permission')
            new_permission.set('{http://schemas.android.com/apk/res/android}name', permission)
            
            root.insert(insertion_index, new_permission)
            insertion_index += 1  # Increment for next permission
            
            result['added'].append(permission)
            print(f"Added permission: {permission}")
        
        result['total_added'] = len(permissions_to_add)
        
        # Register namespace to maintain proper formatting
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        
        # Write back to file with proper formatting
        tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
        
        print(f"\nSuccessfully updated {manifest_path}")
        return result
        
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        return None
    except FileNotFoundError:
        print(f"Error: File '{manifest_path}' not found.")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def print_summary(result):
    """Print a summary of the permission modification results."""
    if result is None:
        return
        
    print("\n" + "="*50)
    print("PERMISSION MODIFICATION SUMMARY")
    print("="*50)
    
    if result['already_present']:
        print("Already present:")
        for perm in result['already_present']:
            print(f"  ✓ {perm}")
    
    if result['added']:
        print("Newly added:")
        for perm in result['added']:
            print(f"  + {perm}")
    
    print(f"\nTotal permissions added: {result['total_added']}")
    
    print("\nFinal manifest should contain:")
    all_permissions = [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE", 
        "android.permission.MANAGE_EXTERNAL_STORAGE"
    ]
    for perm in all_permissions:
        print(f"  <uses-permission android:name=\"{perm}\" />")


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
    result = add_external_storage_permissions(manifest_path)
    
    if result is not None:
        print_summary(result)
        print("\n✓ Manifest modification completed successfully!")
    else:
        print("\n✗ Manifest modification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()