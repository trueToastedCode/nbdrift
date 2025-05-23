package de.truetoastedcode.nbdrift;

import android.util.Log;
import java.lang.Thread;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import android.widget.TextView;

public final class EntryPoint {
    public static final String TAG = "nbdrift";
    
    private final Set<String> loadedClasses = new HashSet<>();
    private boolean targetClassLoader = false;

    private void onClassLoaded(ClassLoader classLoader, String className) {
        if (!targetClassLoader && className.equals("cn.ninebot.ninebot.mainshell.NBApplication")) {
            targetClassLoader = true;
            new NbHook();
        }
    }

    /**
     * Standard hook for ClassLoader.loadClass(String name)
     */
    public Object hookedLoadClass(Hooker.MethodCallback callback) {
        // Get the class name argument
        String className = (String) callback.args[1];
        
        try {
            // Call the original loadClass method
            Object result = callback.backup.invoke(callback.args[0], className);
            
            // Log the class loading only once per class to avoid spam
            if (result != null && !loadedClasses.contains(className)) {
                loadedClasses.add(className);
                ClassLoader loaderInstance = (ClassLoader) callback.args[0];
                String loaderType = loaderInstance.getClass().getName();
                // Log.i(TAG, "Class loaded: " + className + " by " + loaderType);
                onClassLoaded((ClassLoader) callback.args[0], className);
            }
            
            return result;
        } catch (Exception e) {
            // Log.e(TAG, "Error in hookedLoadClass for: " + className, e);
            return null;
        }
    }
    
    /**
     * Hook for ClassLoader.loadClass(String name, boolean resolve)
     */
    public Object hookedLoadClassWithResolve(Hooker.MethodCallback callback) {
        // Get the class name argument
        String className = (String) callback.args[1];
        boolean resolve = (Boolean) callback.args[2];
        
        try {
            // Call the original loadClass method
            Object result = callback.backup.invoke(callback.args[0], className, resolve);
            
            // Log the class loading only once per class to avoid spam
            if (result != null && !loadedClasses.contains(className)) {
                loadedClasses.add(className);
                ClassLoader loaderInstance = (ClassLoader) callback.args[0];
                String loaderType = loaderInstance.getClass().getName();
                // Log.i(TAG, "Class loaded (with resolve=" + resolve + "): " + className + " by " + loaderType);
                onClassLoaded((ClassLoader) callback.args[0], className);
            }
            
            return result;
        } catch (Exception e) {
            // Log.e(TAG, "Error in hookedLoadClassWithResolve for: " + className, e);
            return null;
        }
    }

    /**
     * Initialize all ClassLoader hooks
     */
    public static void init() {
        try {
            Log.i(TAG, "Initializing ClassLoader hooks...");
            
            // Map of ClassLoader types and their loadClass method signatures
            Map<String, Class<?>[]> classLoaderMethodSignatures = new HashMap<>();
            
            // Standard ClassLoader (has both method signatures)
            classLoaderMethodSignatures.put("java.lang.ClassLoader", new Class<?>[] { String.class });
            classLoaderMethodSignatures.put("java.lang.ClassLoader/2", new Class<?>[] { String.class, boolean.class });
            
            // Other ClassLoader types to hook
            String[] classLoaderTypes = {
                "dalvik.system.PathClassLoader",
                "dalvik.system.DexClassLoader", 
                "dalvik.system.InMemoryDexClassLoader",
                "dalvik.system.BaseDexClassLoader",
                "java.lang.BootClassLoader",
                "dalvik.system.DelegateLastClassLoader"
            };
            
            // Create our hook instance
            EntryPoint hookInstance = new EntryPoint();
            
            // Hook the base ClassLoader with both method signatures
            for (Map.Entry<String, Class<?>[]> entry : classLoaderMethodSignatures.entrySet()) {
                String classLoaderName = entry.getKey();
                Class<?>[] paramTypes = entry.getValue();
                
                // Determine which loader we're hooking
                String actualClassName = classLoaderName;
                boolean hasTwoParams = false;
                
                if (classLoaderName.endsWith("/2")) {
                    actualClassName = classLoaderName.substring(0, classLoaderName.length() - 2);
                    hasTwoParams = true;
                }
                
                try {
                    Class<?> classLoaderClass = Class.forName(actualClassName);
                    Method originalMethod = classLoaderClass.getDeclaredMethod("loadClass", paramTypes);
                    
                    // Choose the correct hook method based on parameter count
                    String hookMethodName = hasTwoParams ? "hookedLoadClassWithResolve" : "hookedLoadClass";
                    Method replacementMethod = EntryPoint.class.getDeclaredMethod(
                            hookMethodName, Hooker.MethodCallback.class);
                    
                    Hooker hooker = Hooker.hook(originalMethod, replacementMethod, hookInstance);
                    
                    if (hooker != null) {
                        Log.i(TAG, "Hook created for " + actualClassName + 
                              " with " + paramTypes.length + " parameters");
                    } else {
                        Log.e(TAG, "Failed to hook " + actualClassName);
                    }
                } catch (ClassNotFoundException e) {
                    Log.i(TAG, "ClassLoader " + actualClassName + " not found on this device");
                } catch (NoSuchMethodException e) {
                    Log.i(TAG, actualClassName + " doesn't have loadClass with specified parameters");
                } catch (Exception e) {
                    Log.e(TAG, "Error hooking " + actualClassName, e);
                }
            }
            
            // Now hook all the other ClassLoader types
            for (String loaderType : classLoaderTypes) {
                try {
                    Class<?> classLoaderClass = Class.forName(loaderType);
                    
                    // Check for both method signatures
                    tryHookMethod(classLoaderClass, new Class<?>[] { String.class }, hookInstance, false);
                    tryHookMethod(classLoaderClass, new Class<?>[] { String.class, boolean.class }, hookInstance, true);
                    
                } catch (ClassNotFoundException e) {
                    Log.i(TAG, "ClassLoader " + loaderType + " not found on this device");
                } catch (Exception e) {
                    Log.e(TAG, "Error processing " + loaderType, e);
                }
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Error in initializing ClassLoader hooks", e);
        }
    }
    
    /**
     * Try to hook a method with specified parameters
     */
    private static void tryHookMethod(Class<?> classLoaderClass, Class<?>[] paramTypes, 
                                     EntryPoint hookInstance, boolean hasTwoParams) {
        try {
            // First check if this class has its own implementation or inherits
            Method method = null;
            boolean isDeclaredInClass = false;
            
            try {
                method = classLoaderClass.getDeclaredMethod("loadClass", paramTypes);
                isDeclaredInClass = true;
            } catch (NoSuchMethodException e) {
                // Method might be inherited, try getting it normally
                try {
                    method = classLoaderClass.getMethod("loadClass", paramTypes);
                } catch (NoSuchMethodException e2) {
                    // Neither declared nor inherited with this signature
                    return;
                }
            }
            
            // Skip if the method is inherited (we already hooked the parent)
            if (!isDeclaredInClass) {
                Log.i(TAG, classLoaderClass.getName() + " inherits loadClass with " + 
                      paramTypes.length + " parameters - already hooked via parent");
                return;
            }
            
            // Choose the correct hook method based on parameter count
            String hookMethodName = hasTwoParams ? "hookedLoadClassWithResolve" : "hookedLoadClass";
            Method replacementMethod = EntryPoint.class.getDeclaredMethod(
                    hookMethodName, Hooker.MethodCallback.class);
            
            Hooker hooker = Hooker.hook(method, replacementMethod, hookInstance);
            
            if (hooker != null) {
                Log.i(TAG, "Hook created for " + classLoaderClass.getName() + 
                      " with " + paramTypes.length + " parameters");
            } else {
                Log.e(TAG, "Failed to hook " + classLoaderClass.getName() + 
                      " with " + paramTypes.length + " parameters");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error trying to hook " + classLoaderClass.getName(), e);
        }
    }
}