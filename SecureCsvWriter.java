import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Secure CSV file writer with input validation and proper error handling.
 */
public class SecureCsvWriter {

    private static final Set<Character> DANGEROUS_PREFIXES = Set.of('=', '+', '-', '@', '\t', '\r', '\n');
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile("\\.\\.");

    /**
     * Sanitize a cell value to prevent CSV injection attacks.
     * Escapes potentially dangerous characters that could be interpreted as formulas.
     */
    public static String sanitizeCell(Object value) {
        if (value == null) {
            return "";
        }

        String strValue = value.toString();

        if (!strValue.isEmpty() && DANGEROUS_PREFIXES.contains(strValue.charAt(0))) {
            // Prefix with single quote to prevent formula execution
            strValue = "'" + strValue;
        }

        return strValue;
    }

    /**
     * Escape a value for CSV format (handle quotes and commas).
     */
    private static String escapeCsvValue(String value) {
        // Always quote all fields for safety
        String escaped = value.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    /**
     * Validate and sanitize the file path.
     * Prevents path traversal attacks and ensures safe file location.
     */
    public static Path validateFilepath(String filepath) throws IllegalArgumentException {
        if (filepath == null || filepath.isBlank()) {
            throw new IllegalArgumentException("Filepath cannot be null or empty");
        }

        // Check for path traversal
        if (PATH_TRAVERSAL_PATTERN.matcher(filepath).find()) {
            throw new IllegalArgumentException("Path traversal detected in filepath");
        }

        Path path = Paths.get(filepath).toAbsolutePath().normalize();

        // Ensure it's a .csv file
        if (!filepath.toLowerCase().endsWith(".csv")) {
            throw new IllegalArgumentException("File must have .csv extension");
        }

        return path;
    }

    /**
     * Securely write data to a CSV file.
     *
     * @param filepath   Path to the output CSV file
     * @param data       List of maps containing the data to write
     * @param fieldnames Optional list of column names (inferred from data if null)
     * @throws IOException              If file cannot be written
     * @throws IllegalArgumentException If filepath or data is invalid
     */
    public static void writeCsvSecure(String filepath, List<Map<String, Object>> data, List<String> fieldnames)
            throws IOException, IllegalArgumentException {

        if (data == null || data.isEmpty()) {
            throw new IllegalArgumentException("Data cannot be empty");
        }

        Path safePath = validateFilepath(filepath);

        // Determine fieldnames from data if not provided
        List<String> columns = fieldnames;
        if (columns == null || columns.isEmpty()) {
            columns = new ArrayList<>(data.get(0).keySet());
        }

        // Sanitize fieldnames
        List<String> safeFieldnames = new ArrayList<>();
        for (String field : columns) {
            safeFieldnames.add(sanitizeCell(field));
        }

        // Ensure parent directory exists
        Path parent = safePath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        // Write with secure settings
        try (BufferedWriter writer = Files.newBufferedWriter(safePath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {

            // Write header
            writer.write(formatCsvRow(safeFieldnames));
            writer.newLine();

            // Write data rows
            for (Map<String, Object> row : data) {
                List<String> rowValues = new ArrayList<>();
                for (String field : columns) {
                    Object value = row.get(field);
                    rowValues.add(sanitizeCell(value));
                }
                writer.write(formatCsvRow(rowValues));
                writer.newLine();
            }
        }

        // Set file permissions (Unix-like systems)
        try {
            Set<PosixFilePermission> perms = Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ);
            Files.setPosixFilePermissions(safePath, perms);
        } catch (UnsupportedOperationException e) {
            // Windows doesn't support POSIX permissions
        }
    }

    /**
     * Overload without fieldnames parameter.
     */
    public static void writeCsvSecure(String filepath, List<Map<String, Object>> data) throws IOException {
        writeCsvSecure(filepath, data, null);
    }

    /**
     * Format a list of values as a CSV row with proper quoting.
     */
    private static String formatCsvRow(List<String> values) {
        StringJoiner joiner = new StringJoiner(",");
        for (String value : values) {
            joiner.add(escapeCsvValue(value));
        }
        return joiner.toString();
    }

    /**
     * Securely append data to an existing CSV file.
     *
     * @param filepath Path to the existing CSV file
     * @param data     List of maps to append
     * @throws IOException              If file cannot be written
     * @throws IllegalArgumentException If filepath or data is invalid
     */
    public static void appendCsvSecure(String filepath, List<Map<String, Object>> data)
            throws IOException, IllegalArgumentException {

        if (data == null || data.isEmpty()) {
            throw new IllegalArgumentException("Data cannot be empty");
        }

        Path safePath = validateFilepath(filepath);

        if (!Files.exists(safePath)) {
            throw new FileNotFoundException("CSV file does not exist: " + filepath);
        }

        // Read existing fieldnames from header
        List<String> fieldnames;
        try (BufferedReader reader = Files.newBufferedReader(safePath, StandardCharsets.UTF_8)) {
            String headerLine = reader.readLine();
            if (headerLine == null || headerLine.isBlank()) {
                throw new IllegalArgumentException("Existing CSV file has no headers");
            }
            fieldnames = parseCsvHeader(headerLine);
        }

        // Append data
        try (BufferedWriter writer = Files.newBufferedWriter(safePath, StandardCharsets.UTF_8,
                StandardOpenOption.APPEND)) {

            for (Map<String, Object> row : data) {
                List<String> rowValues = new ArrayList<>();
                for (String field : fieldnames) {
                    // Remove quotes from field name for lookup
                    String cleanField = field.replace("\"", "");
                    Object value = row.get(cleanField);
                    rowValues.add(sanitizeCell(value));
                }
                writer.write(formatCsvRow(rowValues));
                writer.newLine();
            }
        }
    }

    /**
     * Parse CSV header line to extract field names.
     */
    private static List<String> parseCsvHeader(String headerLine) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < headerLine.length(); i++) {
            char c = headerLine.charAt(i);

            if (c == '"') {
                if (inQuotes && i + 1 < headerLine.length() && headerLine.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                fields.add(current.toString().trim());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        fields.add(current.toString().trim());

        return fields;
    }

    // Example usage
    public static void main(String[] args) {
        // Sample data
        List<Map<String, Object>> sampleData = new ArrayList<>();

        Map<String, Object> row1 = new LinkedHashMap<>();
        row1.put("name", "Alice");
        row1.put("email", "alice@example.com");
        row1.put("score", 95);
        sampleData.add(row1);

        Map<String, Object> row2 = new LinkedHashMap<>();
        row2.put("name", "Bob");
        row2.put("email", "bob@example.com");
        row2.put("score", 87);
        sampleData.add(row2);

        // Malicious input that will be sanitized
        Map<String, Object> row3 = new LinkedHashMap<>();
        row3.put("name", "=SUM(A1:A10)");
        row3.put("email", "test@example.com");
        row3.put("score", 100);
        sampleData.add(row3);

        String outputFile = "output.csv";

        try {
            writeCsvSecure(outputFile, sampleData);
            System.out.println("Successfully wrote data to " + outputFile);

            // Append more data
            List<Map<String, Object>> additionalData = new ArrayList<>();
            Map<String, Object> row4 = new LinkedHashMap<>();
            row4.put("name", "Charlie");
            row4.put("email", "charlie@example.com");
            row4.put("score", 92);
            additionalData.add(row4);

            appendCsvSecure(outputFile, additionalData);
            System.out.println("Successfully appended data to " + outputFile);

        } catch (IOException | IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
