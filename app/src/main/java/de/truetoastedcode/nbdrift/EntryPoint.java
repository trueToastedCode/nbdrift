package de.truetoastedcode.nbdrift;

import android.util.Log;
import java.lang.reflect.Method;

public final class EntryPoint {
    private static final String TAG = "nbdrift";

    public void foo(int i) {
        Log.i(TAG, String.format("foo(%1$s) invoked!", i));
    }

    // Replacement method for foo
    public Object hookedFoo(Hooker.MethodCallback callback) {
        // Custom logic before the original method
        int arg = (Integer) callback.args[1]; // Unbox to int
        Log.i(TAG, "Hooked method called with argument: " + arg);
        arg = 0;
        
        try {
            // Call the original method
            return callback.backup.invoke(callback.args[0], arg);
        } catch (Exception e) {
            Log.e(TAG, "Error invoking original method", e);
            return null;
        }
    }

    public static void init() {
        try {
            // Get the original foo method with its parameter type
            Method originalFooMeth = EntryPoint.class.getDeclaredMethod("foo", int.class);
            
            // Create an instance to use as the owner for the hook
            EntryPoint entryPoint = new EntryPoint();
            
            // Get the replacement method
            Method replacementMeth = EntryPoint.class.getDeclaredMethod("hookedFoo", Hooker.MethodCallback.class);
            
            // Create the hook
            Hooker hooker = Hooker.hook(originalFooMeth, replacementMeth, entryPoint);
            
            if (hooker == null) {
                Log.e(TAG, "Failed to create hook");
            } else {
                Log.i(TAG, "Hook created successfully");
            }

            entryPoint.foo(1);
        } catch (Exception e) {
            Log.e(TAG, "Error in init hook", e);
        }
    }
}
