package duck.rkp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;

/** Calls the device's own stable AIDL proxy; owns no keys, network or output artifacts. */
public final class RkpV1Bridge {
    private static final String PREFIX = "android.hardware.security.keymint.";
    private static final String SERVICE = PREFIX + "IRemotelyProvisionedComponent";
    private static final int LIMIT = 0xa000;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("expected exchange directory");
        File directory = new File(args[0]);
        // Status 0: MAC, DeviceInfo, ProtectedData. Status 1: AIDL error code and message.
        // Status 2: transport error. Status 3: invalid HAL response.
        // Every byte string has a big-endian int length.
        byte[] response;
        try {
            response = request(directory);
        } catch (Throwable failure) {
            while (failure instanceof InvocationTargetException && failure.getCause() != null) {
                failure = failure.getCause();
            }
            if (failure.getClass().getName().equals("android.os.ServiceSpecificException")) {
                int code = failure.getClass().getField("errorCode").getInt(failure);
                response = errorReply(1, code, failure.toString());
            } else {
                response = errorReply(2, 0, failure.toString());
            }
        }
        try (FileOutputStream file = new FileOutputStream(new File(directory, "reply.bin"))) {
            file.write(response);
        }
    }

    private static byte[] request(File directory) throws Exception {
        byte[] challenge, maced, p256, x25519;
        try (DataInputStream input = new DataInputStream(
                new FileInputStream(new File(directory, "request.bin")))) {
            challenge = readBytes(input);
            maced = readBytes(input);
            p256 = readBytes(input);
            x25519 = readBytes(input);
            if (input.read() != -1) throw new IOException("trailing request bytes");
        }
        if (challenge.length == 0 || challenge.length > 64 || maced.length == 0) {
            throw new IOException("invalid challenge or MacedPublicKey");
        }
        Class<?> binder = Class.forName("android.os.IBinder");
        Object service = Class.forName("android.os.ServiceManager")
                .getMethod("checkService", String.class).invoke(null, SERVICE + "/default");
        if (service == null) throw new IOException("RKP default service is unavailable");
        Class<?> api = Class.forName(SERVICE);
        Object proxy = Class.forName(SERVICE + "$Stub")
                .getMethod("asInterface", binder).invoke(null, service);
        Object info = api.getMethod("getHardwareInfo").invoke(proxy);
        int curve = info.getClass().getField("supportedEekCurve").getInt(info);
        byte[] eek;
        if (curve == 1) eek = p256;
        else if (curve == 2) eek = x25519;
        // IRPC v3 removed the EEK. Diagnostic probe only: try the v2 request entry point so
        // the report tells whether this HAL accepts a host MacedPublicKey at all.
        else throw new IOException(v3Probe(api, proxy, info, maced, challenge));
        if (eek.length == 0) throw new IOException("server supplied no EEK chain for curve " + curve);

        Class<?> keyClass = Class.forName(PREFIX + "MacedPublicKey");
        Object key = keyClass.getConstructor().newInstance();
        keyClass.getField("macedKey").set(key, maced);
        Object keys = Array.newInstance(keyClass, 1);
        Array.set(keys, 0, key);
        Class<?> deviceClass = Class.forName(PREFIX + "DeviceInfo");
        Class<?> protectedClass = Class.forName(PREFIX + "ProtectedData");
        Object device = deviceClass.getConstructor().newInstance();
        Object protectedData = protectedClass.getConstructor().newInstance();
        byte[] mac = (byte[]) api.getMethod("generateCertificateRequest",
                boolean.class, keys.getClass(), byte[].class, byte[].class,
                deviceClass, protectedClass).invoke(proxy, false, keys, eek, challenge,
                device, protectedData);
        byte[] deviceBytes = (byte[]) deviceClass.getField("deviceInfo").get(device);
        byte[] protectedBytes = (byte[]) protectedClass.getField("protectedData").get(protectedData);
        if (mac == null || mac.length != 32) return errorReply(3, 0, "invalid keysToSign MAC");
        if (deviceBytes == null || deviceBytes.length == 0 || deviceBytes.length > LIMIT) {
            return errorReply(3, 0, "invalid DeviceInfo length");
        }
        if (protectedBytes == null || protectedBytes.length == 0 || protectedBytes.length > LIMIT) {
            return errorReply(3, 0, "invalid ProtectedData length");
        }
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(0);
            writeBytes(output, mac);
            writeBytes(output, deviceBytes);
            writeBytes(output, protectedBytes);
        }
        return buffer.toByteArray();
    }

    private static String describeHardwareInfo(Object info) {
        StringBuilder text = new StringBuilder();
        java.lang.reflect.Field[] fields = info.getClass().getDeclaredFields();
        for (java.lang.reflect.Field field : fields) {
            try {
                field.setAccessible(true);
                Object value = field.get(info);
                if (value instanceof byte[]) value = "<" + ((byte[]) value).length + " bytes>";
                text.append(field.getName()).append('=').append(value).append(' ');
            } catch (Throwable ignored) {
                // Fields that cannot be read are simply omitted from the report.
            }
        }
        return text.toString().trim();
    }

    private static String v3Probe(Class<?> api, Object proxy, Object info, byte[] maced,
            byte[] challenge) {
        StringBuilder details = new StringBuilder();
        details.append("IRPC ").append(describeHardwareInfo(info));
        java.lang.reflect.Method[] methods = api.getDeclaredMethods();
        StringBuilder names = new StringBuilder();
        for (java.lang.reflect.Method method : methods) {
            names.append(method.getName()).append('(').append(method.getParameterCount())
                    .append(") ");
        }
        details.append(" | methods: ").append(names.toString().trim());
        try {
            Class<?> keyClass = Class.forName(PREFIX + "MacedPublicKey");
            Object key = keyClass.getConstructor().newInstance();
            keyClass.getField("macedKey").set(key, maced);
            Object keys = Array.newInstance(keyClass, 1);
            Array.set(keys, 0, key);
            java.lang.reflect.Method call = api.getMethod("generateCertificateRequestV2",
                    keys.getClass(), byte[].class);
            Object csr = call.invoke(proxy, keys, challenge);
            byte[] bytes = csr == null ? new byte[0] : (byte[]) csr;
            details.append(" | GENERATE_CSR_V2_OK length=").append(bytes.length);
            StringBuilder head = new StringBuilder();
            for (int i = 0; i < bytes.length && i < 24; i++) {
                head.append(String.format("%02x", bytes[i]));
            }
            details.append(" head=").append(head);
        } catch (NoSuchMethodException missing) {
            details.append(" | GENERATE_CSR_V2_ABSENT");
        } catch (Throwable failure) {
            details.append(" | GENERATE_CSR_V2_REJECTED ").append(unwrap(failure));
        }
        details.append(" | DEVICE_KEY ").append(deviceKeyProbe(api, proxy, challenge));
        return details.toString();
    }

    private static String deviceKeyProbe(Class<?> api, Object proxy, byte[] challenge) {
        try {
            Class<?> keyClass = Class.forName(PREFIX + "MacedPublicKey");
            java.lang.reflect.Method generate =
                    api.getMethod("generateEcdsaP256KeyPair", boolean.class, keyClass);
            Object deviceKey = keyClass.getConstructor().newInstance();
            Object handle = generate.invoke(proxy, false, deviceKey);
            Object keys = Array.newInstance(keyClass, 1);
            Array.set(keys, 0, deviceKey);
            java.lang.reflect.Method call = api.getMethod("generateCertificateRequestV2",
                    keys.getClass(), byte[].class);
            byte[] csr = (byte[]) call.invoke(proxy, keys, challenge);
            return "CSR_OK length=" + csr.length + " handleLength=" + ((byte[]) handle).length;
        } catch (NoSuchMethodException missing) {
            return "NO_SUCH_METHOD " + missing.getMessage();
        } catch (Throwable failure) {
            return "REJECTED " + unwrap(failure);
        }
    }

    private static String unwrap(Throwable failure) {
        Throwable cause = failure;
        while (cause instanceof InvocationTargetException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        String text = cause.toString();
        try {
            int code = cause.getClass().getField("errorCode").getInt(cause);
            text += " errorCode=" + code;
        } catch (Throwable ignored) {
            // Only ServiceSpecificException carries an error code.
        }
        return text;
    }

    private static byte[] errorReply(int status, int code, String message) throws IOException {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(status);
            if (status == 1) output.writeInt(code);
            if (message.length() > 1024) message = message.substring(0, 1024);
            writeBytes(output, message.getBytes(StandardCharsets.UTF_8));
        }
        return buffer.toByteArray();
    }

    private static byte[] readBytes(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > LIMIT) throw new IOException("invalid input length");
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        return bytes;
    }

    private static void writeBytes(DataOutputStream output, byte[] bytes) throws IOException {
        if (bytes == null || bytes.length > LIMIT) throw new IOException("invalid output length");
        output.writeInt(bytes.length);
        output.write(bytes);
    }
}
