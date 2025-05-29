package de.truetoastedcode.nbdrift;

public class Werkzeug {
    public static String bytes2Text(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append((char) (b & 0xff));
        }
        return sb.toString();
    }

    public static byte[] text2Bytes(String text) {
        char[] chars = text.toCharArray();
        byte[] bytes = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
            bytes[i] = (byte) (chars[i] & 0xff);
        }
        return bytes;
    }
}
