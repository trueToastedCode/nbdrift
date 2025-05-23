package de.truetoastedcode.nbdrift;

public class TypeResolver {
    public static final ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();

    public static Class<?> resolveClass(String className) throws ClassNotFoundException {
        return switch (className) {
            case "boolean" -> boolean.class;
            case "byte"    -> byte.class;
            case "char"    -> char.class;
            case "short"   -> short.class;
            case "int"     -> int.class;
            case "long"    -> long.class;
            case "float"   -> float.class;
            case "double"  -> double.class;
            case "void"    -> void.class;
            default        -> Class.forName(className, true, contextClassLoader);
        };
    }

    public static Class<?>[] resolveClass(String ...classNames) throws ClassNotFoundException {
        Class<?>[] classes = new Class<?>[classNames.length];
        for (int i = 0; i < classNames.length; i++) {
            classes[i] = resolveClass(classNames[i]);
        }
        return classes;
    }
}