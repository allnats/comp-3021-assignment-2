/**
 * Secure CSV file writer with input validation and proper error handling.
 * For Node.js environment.
 */

import * as fs from "fs";
import * as path from "path";

type RowData = Record<string, unknown>;

// Characters that trigger formula interpretation in Excel/Sheets
const DANGEROUS_PREFIXES = ["=", "+", "-", "@", "\t", "\r", "\n"];

/**
 * Sanitize a cell value to prevent CSV injection attacks.
 * Removes or escapes potentially dangerous characters that could be
 * interpreted as formulas in spreadsheet applications.
 */
function sanitizeCell(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }

  let strValue = String(value);

  if (DANGEROUS_PREFIXES.some((prefix) => strValue.startsWith(prefix))) {
    // Prefix with single quote to prevent formula execution
    strValue = "'" + strValue;
  }

  return strValue;
}

/**
 * Escape a value for CSV format (handle quotes and commas).
 * Always quotes all fields for safety.
 */
function escapeCsvValue(value: string): string {
  const escaped = value.replace(/"/g, '""');
  return `"${escaped}"`;
}

/**
 * Validate and sanitize the file path.
 * Prevents path traversal attacks and ensures safe file location.
 */
function validateFilepath(filepath: string): string {
  if (!filepath || filepath.trim() === "") {
    throw new Error("Filepath cannot be null or empty");
  }

  // Check for path traversal
  if (filepath.includes("..")) {
    throw new Error("Path traversal detected in filepath");
  }

  const resolvedPath = path.resolve(filepath);

  // Ensure it's a .csv file
  if (!filepath.toLowerCase().endsWith(".csv")) {
    throw new Error("File must have .csv extension");
  }

  return resolvedPath;
}

/**
 * Format a row of values as a CSV line with proper quoting.
 */
function formatCsvRow(values: string[]): string {
  return values.map(escapeCsvValue).join(",");
}

/**
 * Securely write data to a CSV file.
 *
 * @param filepath - Path to the output CSV file
 * @param data - Array of objects containing the data to write
 * @param fieldnames - Optional array of column names (inferred from data if not provided)
 * @param filePermissions - Unix file permissions (default: 0o644)
 */
export async function writeCsvSecure(
  filepath: string,
  data: RowData[],
  fieldnames?: string[],
  filePermissions: number = 0o644,
): Promise<void> {
  if (!data || data.length === 0) {
    throw new Error("Data cannot be empty");
  }

  const safePath = validateFilepath(filepath);

  // Determine fieldnames from data if not provided
  const columns = fieldnames ?? Object.keys(data[0]);

  // Sanitize fieldnames
  const safeFieldnames = columns.map(sanitizeCell);

  // Ensure parent directory exists
  const parentDir = path.dirname(safePath);
  await fs.promises.mkdir(parentDir, { recursive: true });

  // Build CSV content
  const lines: string[] = [];

  // Header
  lines.push(formatCsvRow(safeFieldnames));

  // Data rows
  for (const row of data) {
    const rowValues = columns.map((field) => sanitizeCell(row[field]));
    lines.push(formatCsvRow(rowValues));
  }

  const content = lines.join("\n") + "\n";

  // Write file
  await fs.promises.writeFile(safePath, content, { encoding: "utf-8" });

  // Set file permissions (Unix-like systems)
  try {
    await fs.promises.chmod(safePath, filePermissions);
  } catch {
    // Windows doesn't support chmod the same way
  }
}

/**
 * Synchronous version of writeCsvSecure for environments that need it.
 */
export function writeCsvSecureSync(
  filepath: string,
  data: RowData[],
  fieldnames?: string[],
  filePermissions: number = 0o644,
): void {
  if (!data || data.length === 0) {
    throw new Error("Data cannot be empty");
  }

  const safePath = validateFilepath(filepath);

  // Determine fieldnames from data if not provided
  const columns = fieldnames ?? Object.keys(data[0]);

  // Sanitize fieldnames
  const safeFieldnames = columns.map(sanitizeCell);

  // Ensure parent directory exists
  const parentDir = path.dirname(safePath);
  fs.mkdirSync(parentDir, { recursive: true });

  // Build CSV content
  const lines: string[] = [];

  // Header
  lines.push(formatCsvRow(safeFieldnames));

  // Data rows
  for (const row of data) {
    const rowValues = columns.map((field) => sanitizeCell(row[field]));
    lines.push(formatCsvRow(rowValues));
  }

  const content = lines.join("\n") + "\n";

  // Write file
  fs.writeFileSync(safePath, content, { encoding: "utf-8" });

  // Set file permissions
  try {
    fs.chmodSync(safePath, filePermissions);
  } catch {
    // Windows doesn't support chmod the same way
  }
}

/**
 * Parse a CSV header line to extract field names.
 */
function parseCsvHeader(headerLine: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < headerLine.length; i++) {
    const c = headerLine[i];

    if (c === '"') {
      if (inQuotes && headerLine[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (c === "," && !inQuotes) {
      fields.push(current.trim());
      current = "";
    } else {
      current += c;
    }
  }
  fields.push(current.trim());

  return fields;
}

/**
 * Securely append data to an existing CSV file.
 *
 * @param filepath - Path to the existing CSV file
 * @param data - Array of objects to append
 */
export async function appendCsvSecure(
  filepath: string,
  data: RowData[],
): Promise<void> {
  if (!data || data.length === 0) {
    throw new Error("Data cannot be empty");
  }

  const safePath = validateFilepath(filepath);

  // Check if file exists
  try {
    await fs.promises.access(safePath);
  } catch {
    throw new Error(`CSV file does not exist: ${filepath}`);
  }

  // Read existing fieldnames from header
  const content = await fs.promises.readFile(safePath, { encoding: "utf-8" });
  const firstLine = content.split("\n")[0];

  if (!firstLine || firstLine.trim() === "") {
    throw new Error("Existing CSV file has no headers");
  }

  const fieldnames = parseCsvHeader(firstLine);

  // Build rows to append
  const lines: string[] = [];

  for (const row of data) {
    const rowValues = fieldnames.map((field) => {
      // Remove quotes from field name for lookup
      const cleanField = field.replace(/"/g, "");
      return sanitizeCell(row[cleanField]);
    });
    lines.push(formatCsvRow(rowValues));
  }

  const appendContent = lines.join("\n") + "\n";

  // Append to file
  await fs.promises.appendFile(safePath, appendContent, { encoding: "utf-8" });
}

/**
 * Synchronous version of appendCsvSecure.
 */
export function appendCsvSecureSync(filepath: string, data: RowData[]): void {
  if (!data || data.length === 0) {
    throw new Error("Data cannot be empty");
  }

  const safePath = validateFilepath(filepath);

  // Check if file exists
  if (!fs.existsSync(safePath)) {
    throw new Error(`CSV file does not exist: ${filepath}`);
  }

  // Read existing fieldnames from header
  const content = fs.readFileSync(safePath, { encoding: "utf-8" });
  const firstLine = content.split("\n")[0];

  if (!firstLine || firstLine.trim() === "") {
    throw new Error("Existing CSV file has no headers");
  }

  const fieldnames = parseCsvHeader(firstLine);

  // Build rows to append
  const lines: string[] = [];

  for (const row of data) {
    const rowValues = fieldnames.map((field) => {
      const cleanField = field.replace(/"/g, "");
      return sanitizeCell(row[cleanField]);
    });
    lines.push(formatCsvRow(rowValues));
  }

  const appendContent = lines.join("\n") + "\n";

  // Append to file
  fs.appendFileSync(safePath, appendContent, { encoding: "utf-8" });
}

// Example usage
async function main() {
  // Sample data
  const sampleData: RowData[] = [
    { name: "Alice", email: "alice@example.com", score: 95 },
    { name: "Bob", email: "bob@example.com", score: 87 },
    { name: "=SUM(A1:A10)", email: "test@example.com", score: 100 }, // Malicious input sanitized
  ];

  const outputFile = "output.csv";

  try {
    await writeCsvSecure(outputFile, sampleData);
    console.log(`Successfully wrote data to ${outputFile}`);

    // Append more data
    const additionalData: RowData[] = [
      { name: "Charlie", email: "charlie@example.com", score: 92 },
    ];
    await appendCsvSecure(outputFile, additionalData);
    console.log(`Successfully appended data to ${outputFile}`);
  } catch (error) {
    console.error(`Error: ${(error as Error).message}`);
  }
}

// Run if executed directly
main();
