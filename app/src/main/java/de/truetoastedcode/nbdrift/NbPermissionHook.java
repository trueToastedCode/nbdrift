package de.truetoastedcode.nbdrift;

import java.lang.reflect.*;
import android.util.Log;

public class NbPermissionHook {
    public Object myIsFactoryGroup(Hooker.MethodCallback callback) {
        return (Object) true;
    }

    public NbPermissionHook() {
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
