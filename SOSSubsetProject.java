import java.util.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * DSA-3 (25CS2103E) — SOS Dynamic Programming Based Subset Optimization
 * and Query Engine, with registration, login, and login history.
 *
 * Files created in the same directory:
 *   sos_users.txt        - usernames and SHA-256 password hashes
 *   sos_login_history.txt - login attempts with date/time and status
 */
public class SOSSubsetProject {

    static long[] sosTable;
    static int[] elements;
    static int n, size;

    static final String USERS_FILE = "sos_users.txt";
    static final String HISTORY_FILE = "sos_login_history.txt";
    static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        if (!authenticate(sc)) {
            System.out.println("Too many failed attempts. Exiting program.");
            sc.close();
            return;
        }

        System.out.print("\nEnter the set as comma-separated integers (blank for default 3,5,2,7,4,6): ");
        String line = sc.nextLine().trim();

        try {
            elements = line.isEmpty() ? new int[]{3, 5, 2, 7, 4, 6} : parseInts(line);
        } catch (NumberFormatException e) {
            System.out.println("Invalid input. Please enter integers separated by commas.");
            sc.close();
            return;
        }

        n = elements.length;
        if (n == 0) {
            System.out.println("Set can't be empty.");
            sc.close();
            return;
        }
        if (n > 20) {
            System.out.println("n must be <= 20 (2^20 already exceeds 1,048,576 subsets).");
            sc.close();
            return;
        }
        size = 1 << n;

        precomputeSOS();
        System.out.println("\nSet: " + Arrays.toString(elements)
                + "  (n = " + n + ", " + size + " subsets precomputed)");

        boolean running = true;
        while (running) {
            System.out.println("\n1) Show subset table");
            System.out.println("2) Ask a query (pick a subset)");
            System.out.println("3) Run performance test (SOS DP vs brute force)");
            System.out.println("4) Show login history");
            System.out.println("0) Exit");
            System.out.print("Choice: ");

            switch (sc.nextLine().trim()) {
                case "1": showTable(); break;
                case "2": askQuery(sc); break;
                case "3": performanceTest(sc); break;
                case "4": showLoginHistory(); break;
                case "0": running = false; break;
                default: System.out.println("Invalid choice.");
            }
        }
        sc.close();
        System.out.println("Logged out. Goodbye!");
    }

    // ---------- Registration and login ----------

    static boolean authenticate(Scanner sc) {
        int failedAttempts = 0;

        while (true) {
            System.out.println("\n===== SOS PROJECT LOGIN =====");
            System.out.println("1) Login");
            System.out.println("2) Register new account");
            System.out.println("3) View login history");
            System.out.println("0) Exit");
            System.out.print("Choose: ");
            String choice = sc.nextLine().trim();

            if (choice.equals("0")) return false;

            if (choice.equals("2")) {
                register(sc);
                continue;
            }

            if (choice.equals("3")) {
                showLoginHistory();
                continue;
            }

            if (!choice.equals("1")) {
                System.out.println("Invalid choice.");
                continue;
            }

            System.out.print("Username: ");
            String username = sc.nextLine().trim();
            System.out.print("Password: ");
            String password = sc.nextLine();

            if (verifyUser(username, password)) {
                addHistory(username, "SUCCESS");
                System.out.println("Login successful. Welcome, " + username + "!");
                return true;
            } else {
                addHistory(username.isEmpty() ? "(blank)" : username, "FAILED");
                failedAttempts++;
                System.out.println("Invalid username or password.");
                if (failedAttempts >= 3) return false;
            }
        }
    }

    static void register(Scanner sc) {
        System.out.println("\n===== REGISTER ACCOUNT =====");
        System.out.print("Create username: ");
        String username = sc.nextLine().trim();

        if (username.isEmpty() || username.contains("|")) {
            System.out.println("Username cannot be blank or contain '|'.");
            return;
        }
        if (userExists(username)) {
            System.out.println("That username already exists.");
            return;
        }

        System.out.print("Create password (at least 6 characters): ");
        String password = sc.nextLine();
        if (password.length() < 6 || password.contains("|")) {
            System.out.println("Password must be at least 6 characters and cannot contain '|'.");
            return;
        }

        try (PrintWriter out = new PrintWriter(new FileWriter(USERS_FILE, true))) {
            out.println(username + "|" + sha256(password));
            System.out.println("Registration successful. You can now log in.");
        } catch (IOException e) {
            System.out.println("Could not save account: " + e.getMessage());
        }
    }

    static boolean userExists(String username) {
        File file = new File(USERS_FILE);
        if (!file.exists()) return false;

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String record;
            while ((record = br.readLine()) != null) {
                String[] parts = record.split("\\|", 2);
                if (parts.length == 2 && parts[0].equals(username)) return true;
            }
        } catch (IOException e) {
            System.out.println("Could not read accounts: " + e.getMessage());
        }
        return false;
    }

    static boolean verifyUser(String username, String password) {
        File file = new File(USERS_FILE);
        if (!file.exists()) return false;

        String enteredHash = sha256(password);
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String record;
            while ((record = br.readLine()) != null) {
                String[] parts = record.split("\\|", 2);
                if (parts.length == 2 && parts[0].equals(username)
                        && parts[1].equals(enteredHash)) {
                    return true;
                }
            }
        } catch (IOException e) {
            System.out.println("Could not read accounts: " + e.getMessage());
        }
        return false;
    }

    // Stores a hash instead of saving the plain-text password.
    static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (byte b : hash) result.append(String.format("%02x", b));
            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }

    static void addHistory(String username, String status) {
        String time = LocalDateTime.now().format(TIME_FORMAT);
        try (PrintWriter out = new PrintWriter(new FileWriter(HISTORY_FILE, true))) {
            out.println(time + " | Username: " + username + " | Status: " + status);
        } catch (IOException e) {
            System.out.println("Could not save login history: " + e.getMessage());
        }
    }

    static void showLoginHistory() {
        System.out.println("\n===== LOGIN HISTORY =====");
        File file = new File(HISTORY_FILE);
        if (!file.exists()) {
            System.out.println("No login history available yet.");
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String record;
            boolean found = false;
            while ((record = br.readLine()) != null) {
                System.out.println(record);
                found = true;
            }
            if (!found) System.out.println("No login history available yet.");
        } catch (IOException e) {
            System.out.println("Could not read login history: " + e.getMessage());
        }
    }

    // ---------- SOS Dynamic Programming ----------

    /** Precompute the sum of every subset in O(n * 2^n). */
    static void precomputeSOS() {
        sosTable = new long[size];
        for (int i = 0; i < n; i++) sosTable[1 << i] = elements[i];
        for (int i = 0; i < n; i++) {
            for (int mask = 0; mask < size; mask++) {
                if ((mask & (1 << i)) != 0) {
                    sosTable[mask] += sosTable[mask ^ (1 << i)];
                }
            }
        }
    }

    /** Brute force baseline: O(n) per query, no preprocessing. */
    static long bruteForceQuery(int mask) {
        long sum = 0;
        for (int i = 0; i < n; i++) {
            if ((mask & (1 << i)) != 0) sum += elements[i];
        }
        return sum;
    }

    static void showTable() {
        int rows = Math.min(size, 20);
        System.out.printf("%n%-6s %-10s %-24s %s%n", "mask", "binary", "subset", "sum");
        for (int mask = 0; mask < rows; mask++) {
            System.out.printf("%-6d %-10s %-24s %d%n",
                    mask, toBinary(mask), subsetOf(mask), sosTable[mask]);
        }
        if (size > rows) {
            System.out.println("... (" + (size - rows) + " more of "
                    + size + " subsets not shown)");
        }
    }

    static void askQuery(Scanner sc) {
        System.out.println("Pick elements by index for your subset (indices: 0 to " + (n - 1) + ").");
        System.out.println("Set = " + Arrays.toString(elements));
        System.out.print("Enter indices, comma separated (e.g. 0,2,4), or blank for none: ");
        String line = sc.nextLine().trim();
        int mask = 0;

        if (!line.isEmpty()) {
            try {
                for (int idx : parseInts(line)) {
                    if (idx < 0 || idx >= n) {
                        System.out.println("Index " + idx + " out of range, ignored.");
                        continue;
                    }
                    mask |= (1 << idx);
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid indices. Use integers separated by commas.");
                return;
            }
        }

        System.out.println("Mask: " + toBinary(mask) + "  Subset: " + subsetOf(mask));
        System.out.println("  SOS DP lookup (O(1)) : " + sosTable[mask]);
        System.out.println("  Brute force  (O(n))  : " + bruteForceQuery(mask));
    }

    static void performanceTest(Scanner sc) {
        System.out.print("How many random queries to time? ");
        int q;
        try {
            q = Integer.parseInt(sc.nextLine().trim());
            if (q < 0 || q > 10_000_000) {
                System.out.println("Enter a query count between 0 and 10,000,000.");
                return;
            }
        } catch (NumberFormatException e) {
            System.out.println("Not a number.");
            return;
        }

        Random rnd = new Random(42);
        int[] masks = new int[q];
        for (int i = 0; i < q; i++) masks[i] = rnd.nextInt(size);

        long t0 = System.nanoTime();
        long checksum1 = 0;
        for (int mask : masks) checksum1 += bruteForceQuery(mask);
        long bruteNanos = System.nanoTime() - t0;

        long t1 = System.nanoTime();
        precomputeSOS();
        long precomputeNanos = System.nanoTime() - t1;

        long t2 = System.nanoTime();
        long checksum2 = 0;
        for (int mask : masks) checksum2 += sosTable[mask];
        long lookupNanos = System.nanoTime() - t2;
        long sosNanos = precomputeNanos + lookupNanos;

        System.out.printf("%nResults for %,d random queries (n = %d, %,d subsets)%n",
                q, n, size);
        System.out.printf("  Brute force : %,.3f ms%n", bruteNanos / 1_000_000.0);
        System.out.printf("  SOS DP      : %,.3f ms  (precompute %,.3f ms + %,d lookups %,.3f ms)%n",
                sosNanos / 1_000_000.0, precomputeNanos / 1_000_000.0,
                q, lookupNanos / 1_000_000.0);
        if (sosNanos < bruteNanos && sosNanos > 0) {
            System.out.printf("  SOS DP was %.1fx faster across these %,d queries.%n",
                    (double) bruteNanos / sosNanos, q);
        } else {
            System.out.println("  Precompute cost hasn't been recovered yet — try more queries to see it cross over.");
        }
        if (checksum1 != checksum2) System.out.println("  Warning: checksum mismatch.");
    }

    static String toBinary(int mask) {
        String s = Integer.toBinaryString(mask);
        while (s.length() < n) s = "0" + s;
        return s;
    }

    static String subsetOf(int mask) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (int i = 0; i < n; i++) {
            if ((mask & (1 << i)) != 0) {
                if (!first) sb.append(", ");
                sb.append(elements[i]);
                first = false;
            }
        }
        return sb.append("}").toString();
    }

    static int[] parseInts(String line) {
        String[] parts = line.trim().split("\\s*,\\s*|\\s+");
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = Integer.parseInt(parts[i].trim());
        }
        return out;
    }
}
