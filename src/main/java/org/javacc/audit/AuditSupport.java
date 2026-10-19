package org.javacc.audit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** Small JDK 8 equivalents of the collection and UTF-8 I/O conveniences used by the analyzer. */
final class AuditSupport {
    private AuditSupport() {}

    @SafeVarargs
    static <T> List<T> list(T... values) {
        List<T> result = new ArrayList<>(values.length);
        for (T value : values) {
            result.add(Objects.requireNonNull(value));
        }
        return Collections.unmodifiableList(result);
    }

    @SafeVarargs
    static <T> Set<T> set(T... values) {
        Set<T> result = new LinkedHashSet<>();
        for (T value : values) {
            if (!result.add(Objects.requireNonNull(value))) {
                throw new IllegalArgumentException("Duplicate set element");
            }
        }
        return Collections.unmodifiableSet(result);
    }

    static String readString(Path path) throws IOException {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    static void writeString(Path path, String value) throws IOException {
        Files.write(path, value.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] bytes = new byte[8192];
        int count;
        while ((count = input.read(bytes)) != -1) {
            output.write(bytes, 0, count);
        }
        return output.toByteArray();
    }

    static boolean isBlank(String value) {
        return value.codePoints().allMatch(Character::isWhitespace);
    }
}
