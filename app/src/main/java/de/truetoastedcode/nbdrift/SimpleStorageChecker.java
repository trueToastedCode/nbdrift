package de.truetoastedcode.nbdrift;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;
import android.os.Environment;

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
            // Use proper Android API to get external storage directory
            File externalStorageDir = Environment.getExternalStorageDirectory();
            
            // Check if external storage is available and mounted
            String state = Environment.getExternalStorageState();
            if (!Environment.MEDIA_MOUNTED.equals(state)) {
                return false;
            }
            
            // Check if directory exists and is readable
            if (!externalStorageDir.exists() || !externalStorageDir.canRead()) {
                return false;
            }
            
            // Test actual write capability
            File testFile = new File(externalStorageDir, ".temp_access_test");
            boolean canWrite = testFile.createNewFile();
            
            if (canWrite) {
                testFile.delete(); // Clean up
            }
            
            return canWrite;
            
        } catch (SecurityException e) {
            // Handle permission denied
            return false;
        } catch (IOException e) {
            // Handle I/O errors
            return false;
        } catch (Exception e) {
            // Handle any other unexpected errors
            return false;
        }
    }
}