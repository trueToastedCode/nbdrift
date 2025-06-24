package de.truetoastedcode.nbdrift;

import java.lang.reflect.*;
import android.util.Log;
import java.io.IOException;
import java.nio.file.Files;
import android.os.Environment;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.lang.NumberFormatException;

public class NbPermissionHook {
    public Object myIsFactoryGroup(Hooker.MethodCallback callback) {
        return (Object) true;
    }

    public NbPermissionHook() {
        boolean prmSpoof = true;

        if (SimpleStorageChecker.canAccessStorage()) {
            Path prmSpoofPath = Paths.get(
                Environment.getExternalStorageDirectory().getAbsolutePath(),
                "nbdrift",
                "prm-spoof.txt"
            );
            if (Files.exists(prmSpoofPath)) {
                try {
                    prmSpoof = Integer.parseInt((new String(Files.readAllBytes(prmSpoofPath))).trim()) != 0;
                } catch (IOException e) {
                    Log.e(EntryPoint.TAG, "Error reading permission spoof file: " + e.getMessage(), e);
                } catch (NumberFormatException e) {
                    Log.e(EntryPoint.TAG, "Error parsing permission spoof file: " + e.getMessage(), e);
                }
            } else {
                Log.d(EntryPoint.TAG, "Permission spoof file does not exist at: " + prmSpoofPath.toString());
            }
        } else {
            Log.e(EntryPoint.TAG, "Cannot access storage. Permission may be missing.");
        }

        Log.d(EntryPoint.TAG, "Permission spoof : " + (prmSpoof ? "Enabled" : "Disabled"));

        if (!prmSpoof) return;

        try {
            Class<?> UserPermissionProviderImplClass = TypeResolver.resolveClass("cn.ninebot.account.UserPermissionProviderImpl");

            Method UserPermissionProviderImplIsFactoryGroupMeth = UserPermissionProviderImplClass.getMethod("isFactoryGroup", String.class);

            Hooker interceptHooker = Hooker.hook(
                UserPermissionProviderImplIsFactoryGroupMeth,
                this.getClass().getMethod("myIsFactoryGroup", Hooker.MethodCallback.class),
                this
            );

            if (interceptHooker == null) {
                throw new IllegalStateException("Failed to hook myIsFactoryGroup method");
            }

            Log.d(EntryPoint.TAG, "UserPermissionProviderImpl hook installed successfully");
        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "NbPermissionHook(): [error] " + e, e);
        }
    }
}
