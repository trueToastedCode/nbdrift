package de.truetoastedcode.nbdrift;

import android.util.Log;
import java.lang.reflect.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;
import android.os.Environment;

public class HookDeviceData {
    private Class<?>
    CommandDispatcherClass,
    CommandClass,
    NbFrameClass,
    NbBluetoothDeviceClass;

    private Field
    NbFrameDataField;

    private Method
    CommandGetTagMeth;

    private String
    snSpoof;

    public HookDeviceData() {
        setupHookDeviceBean();

        if (SimpleStorageChecker.canAccessStorage()) {
            Path snSpoofPath = Paths.get(
                Environment.getExternalStorageDirectory().getAbsolutePath(),
                "nbdrift",
                "sn-spoof.txt"
            );
            if (Files.exists(snSpoofPath)) {
                try {
                    snSpoof = (new String(Files.readAllBytes(snSpoofPath))).trim();
                } catch (IOException e) {
                    Log.e(EntryPoint.TAG, "Error reading payload file: " + e.getMessage(), e);
                }
            } else {
                Log.d(EntryPoint.TAG, "Serial number spoof file does not exist at: " + snSpoofPath.toString());
            }
        } else {
            Log.e(EntryPoint.TAG, "Cannot access storage. Permission may be missing.");
        }
    }

    public Object myNotifyCommandQueue(Hooker.MethodCallback callback) {
        try {
            Object
            thizz = callback.args[0],
            command = callback.args[1],
            frame = callback.args[2];

            String commandTag = (String) CommandGetTagMeth.invoke(command);
            byte[] frameData = (byte[]) NbFrameDataField.get(frame);

            if (
                commandTag == null ||
                commandTag.isEmpty() ||
                frameData == null ||
                frameData.length == 0
            ) {
                return callback.backup.invoke(thizz, command, frame);
            }

            if (snSpoof != null && commandTag.equals("rSN")) {
                String realSN = Werkzeug.bytes2Text(frameData);
                NbFrameDataField.set(frame, Werkzeug.text2Bytes(snSpoof));
                Log.d(EntryPoint.TAG, String.format("myNotifyCommandQueue(): SN spoof applied %s -> %s", realSN, snSpoof));
            }

            return callback.backup.invoke(thizz, command, frame);
        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "myNotifyCommandQueue(): Hook implementation failed: " + e, e);
            return null;
        }
    }

    public Object mySetSn(Hooker.MethodCallback callback) {
        try {
            Object thizz = callback.args[0];
            String realSn = (String) callback.args[1];

            if (snSpoof == null) {
                return callback.backup.invoke(thizz, realSn);
            }

            Log.d(EntryPoint.TAG, String.format("mySetSn(): SN spoof applied %s -> %s", realSn, snSpoof));

            return callback.backup.invoke(thizz, snSpoof);
        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "mySetSn(): Hook implementation failed: " + e, e);
            return null;
        }
    }

    private void setupHookDeviceBean() {
        try {
            CommandDispatcherClass = TypeResolver.resolveClass("cn.ninebot.library.nbbluetooth.command.CommandDispatcher");
            CommandClass = TypeResolver.resolveClass("cn.ninebot.library.nbbluetooth.command.Command");
            NbFrameClass = TypeResolver.resolveClass("cn.ninebot.library.nbbluetooth.command.NbFrame");
            NbBluetoothDeviceClass = TypeResolver.resolveClass("cn.ninebot.library.nbbluetooth.NbBluetoothDevice");

            NbFrameDataField = NbFrameClass.getDeclaredField("data");
            NbFrameDataField.setAccessible(true);

            Method CommandDispatcherNotifyCommandQueueMeth = CommandDispatcherClass.getDeclaredMethod(
                "notifyCommandQueue", CommandClass, NbFrameClass);
            CommandDispatcherNotifyCommandQueueMeth.setAccessible(true);
            CommandGetTagMeth = CommandClass.getMethod("getTag");
            Method NbBluetoothDeviceSetSnMeth = NbBluetoothDeviceClass.getMethod("setSn", String.class);

            Hooker notifyCommandQueueHook = Hooker.hook(
                CommandDispatcherNotifyCommandQueueMeth,
                this.getClass().getMethod("myNotifyCommandQueue", Hooker.MethodCallback.class),
                this
            );

            if (notifyCommandQueueHook == null) {
                throw new IllegalStateException("Failed to hook notifyCommandQueue");
            }

            Hooker nbBluetoothDeviceSetSnHook = Hooker.hook(
                NbBluetoothDeviceSetSnMeth,
                this.getClass().getMethod("mySetSn", Hooker.MethodCallback.class),
                this
            );

            if (nbBluetoothDeviceSetSnHook == null) {
                throw new IllegalStateException("Failed to hook setSn");
            }

            Log.d(EntryPoint.TAG, "setupHookDeviceBean(): Hook installed successfully");
        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "setupHookDeviceBean(): Setup failed: " + e, e);
        }
    }
}
