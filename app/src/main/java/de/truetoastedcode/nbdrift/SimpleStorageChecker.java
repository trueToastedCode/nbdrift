package de.truetoastedcode.nbdrift;

import java.io.File;

public class SimpleStorageChecker {
    private static Boolean canAccess = null;
    
    /**
     * Performs one-time check if we can read/write to /storage/emulated/0
     * Results are cached for subsequent calls
     */
    public static boolean canAccessStorage() {
        if (canAccess == null) {
            canAccess = performStorageCheck();
        }
        return canAccess;
    }
    
    /**
     * Force re-check of storage access (ignores cached result)
     */
    public static boolean recheckStorage() {
        canAccess = performStorageCheck();
        return canAccess;
    }
    
    private static boolean performStorageCheck() {
        try {
            File storageDir = new File("/storage/emulated/0");
            
            // Check if directory exists and is readable
            if (!storageDir.exists() || !storageDir.canRead()) {
                return false;
            }
            
            // Test actual write capability
            File testFile = new File(storageDir, ".temp_access_test");
            boolean canWrite = testFile.createNewFile();
            
            if (canWrite) {
                testFile.delete(); // Clean up
            }
            
            return canWrite;
            
        } catch (Exception e) {
            return false;
        }
    }
}