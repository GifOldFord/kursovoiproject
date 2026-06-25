import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/**
 * Полноценное приложение-шифратор
 * Реализует гибридную криптосистему: PBKDF2 + AES-256-GCM + RSA-2048
 * Сохраняет ключи и зашифрованные данные в файлы
 */
public class SecureCryptoApp {

    // Сигнатура формата файла (Hybrid Crypto Package)
    private static final byte[] MAGIC = "HCRP".getBytes();
    private static final byte VERSION = 1;
    private static final String KEYS_DIR = "crypto_keys";
    private static final String DATA_DIR = "crypto_data";

    private static Scanner scanner = new Scanner(System.in);

    // Текущие загруженные ключи
    private static KeyPair senderKeys = null;
    private static KeyPair recipientKeys = null;

    public static void main(String[] args) {
        // Создание рабочих директорий
        new File(KEYS_DIR).mkdirs();
        new File(DATA_DIR).mkdirs();

        printBanner();

        boolean running = true;
        while (running) {
            showMainMenu();
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1": keyManagementMenu(); break;
                case "2": encryptTextToFile(); break;
                case "3": encryptFileToFile(); break;
                case "4": decryptFromFile(); break;
                case "5": showFileInfo(); break;
                case "6": showCurrentKeys(); break;
                case "0":
                    running = false;
                    System.out.println("\n👋 Завершение работы. До свидания!");
                    break;
                default:
                    System.out.println("\n❌ Неверный выбор.\n");
            }
        }
        scanner.close();
    }

    // ==================== ИНТЕРФЕЙС ====================

    private static void printBanner() {
        System.out.println("\n╔═══════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                                                                         ║");
        System.out.println("║                      🔐 SECURE CRYPTO APP v1.0                          ║");
        System.out.println("║                      Гибридная криптосистема Шуракова Н.А               ║");
        System.out.println("║                      AES-256-GCM + RSA-2048 + PBKDF2                    ║");
        System.out.println("║                                                                         ║");
        System.out.println("╚═════════════════════════════════════════════════════════════════════════╝\n");
    }

    private static void showMainMenu() {
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("ГЛАВНОЕ МЕНЮ:");
        System.out.println("   [1]  Управление ключами (генерация / загрузка)");
        System.out.println("   [2]  Зашифровать текст → файл");
        System.out.println("   [3]  Зашифровать файл → файл");
        System.out.println("   [4]  Расшифровать файл");
        System.out.println("   [5]  Информация о зашифрованном файле");
        System.out.println("   [6]  Показать текущие ключи");
        System.out.println("   [0]  Выход");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.print("▶ Ваш выбор: ");
    }

    private static void keyManagementMenu() {
        System.out.println("\n УПРАВЛЕНИЕ КЛЮЧАМИ");
        System.out.println("   [1] Сгенерировать новую пару ключей (отправитель)");
        System.out.println("   [2] Сгенерировать новую пару ключей (получатель)");
        System.out.println("   [3] Загрузить ключи отправителя из файла");
        System.out.println("   [4] Загрузить ключи получателя из файла");
        System.out.println("   [5] Список сохранённых ключей");
        System.out.println("   [0] ← Назад");
        System.out.print(" Выбор: ");

        String choice = scanner.nextLine().trim();
        switch (choice) {
            case "1": generateAndSaveKeys("sender"); break;
            case "2": generateAndSaveKeys("recipient"); break;
            case "3": senderKeys = loadKeys("sender"); break;
            case "4": recipientKeys = loadKeys("recipient"); break;
            case "5": listSavedKeys(); break;
            case "0": break;
            default: System.out.println(" Неверный выбор\n");
        }
    }

    // ==================== УПРАВЛЕНИЕ КЛЮЧАМИ ====================

    private static void generateAndSaveKeys(String role) {
        try {
            System.out.println("\n️  Генерация RSA-2048 ключей для роли: " + role);
            System.out.print("   Имя для сохранения (например, pepe): ");
            String name = scanner.nextLine().trim();
            if (name.isEmpty()) name = role + "_" + System.currentTimeMillis();

            System.out.print("   Пароль для защиты закрытого ключа: ");
            String password = scanner.nextLine();

            System.out.println("    Генерация (может занять 1-2 секунды)...");
            long start = System.currentTimeMillis();

            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair kp = gen.generateKeyPair();

            long elapsed = System.currentTimeMillis() - start;

            // Сохранение ключей
            String pubFile = KEYS_DIR + "/" + name + ".pub";
            String privFile = KEYS_DIR + "/" + name + ".key";

            savePublicKey(kp.getPublic(), pubFile);
            savePrivateKey(kp.getPrivate(), privFile, password);

            // Загрузка в память
            if (role.equals("sender")) senderKeys = kp;
            else recipientKeys = kp;

            System.out.println("    Ключи сгенерированы за " + elapsed + " мс");
            System.out.println("    Открытый ключ:   " + pubFile);
            System.out.println("    Закрытый ключ:   " + privFile);
            System.out.println("    Закрытый ключ зашифрован вашим паролем\n");

        } catch (Exception e) {
            System.out.println("    Ошибка: " + e.getMessage() + "\n");
        }
    }

    private static KeyPair loadKeys(String role) {
        try {
            System.out.println("\n Загрузка ключей (" + role + ")");
            listSavedKeys();

            System.out.print("   Введите имя (без расширения): ");
            String name = scanner.nextLine().trim();
            if (name.isEmpty()) {
                System.out.println("    Имя не указано\n");
                return null;
            }

            System.out.print("   Пароль для закрытого ключа: ");
            String password = scanner.nextLine();

            String pubFile = KEYS_DIR + "/" + name + ".pub";
            String privFile = KEYS_DIR + "/" + name + ".key";

            PublicKey pub = loadPublicKey(pubFile);
            PrivateKey priv = loadPrivateKey(privFile, password);

            KeyPair kp = new KeyPair(pub, priv);
            System.out.println("    Ключи загружены успешно\n");
            return kp;

        } catch (Exception e) {
            System.out.println("    Ошибка загрузки: " + e.getMessage() + "\n");
            return null;
        }
    }

    private static void listSavedKeys() {
        System.out.println("\n Сохранённые ключи в папке '" + KEYS_DIR + "':");
        File dir = new File(KEYS_DIR);
        File[] files = dir.listFiles((d, n) -> n.endsWith(".pub"));

        if (files == null || files.length == 0) {
            System.out.println("   (пусто)\n");
            return;
        }

        Set<String> names = new TreeSet<>();
        for (File f : files) {
            names.add(f.getName().replace(".pub", ""));
        }

        int i = 1;
        for (String name : names) {
            File pub = new File(KEYS_DIR + "/" + name + ".pub");
            File priv = new File(KEYS_DIR + "/" + name + ".key");
            System.out.println("   [" + i + "] " + name +
                    "  (публичный: " + (pub.exists() ? "+" : "-") +
                    ", закрытый: " + (priv.exists() ? "+" : "-") + ")");
            i++;
        }
        System.out.println();
    }

    private static void showCurrentKeys() {
        System.out.println("\n  ТЕКУЩИЕ ЗАГРУЖЕННЫЕ КЛЮЧИ");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        if (senderKeys == null) {
            System.out.println("    Отправитель: ключи НЕ загружены");
        } else {
            System.out.println("    Отправитель: ключи загружены");
            System.out.println("      Публичный ключ (SHA-256): " +
                    sha256Short(senderKeys.getPublic().getEncoded()));
        }

        if (recipientKeys == null) {
            System.out.println("    Получатель: ключи НЕ загружены");
        } else {
            System.out.println("    Получатель: ключи загружены");
            System.out.println("      Публичный ключ (SHA-256): " +
                    sha256Short(recipientKeys.getPublic().getEncoded()));
        }
        System.out.println();
    }

    // ==================== ШИФРОВАНИЕ ТЕКСТА ====================

    private static void encryptTextToFile() {
        try {
            if (senderKeys == null || recipientKeys == null) {
                System.out.println("\n Сначала загрузите ключи отправителя и получателя (пункт 1)\n");
                return;
            }

            System.out.println("\n ШИФРОВАНИЕ ТЕКСТА В ФАЙЛ");
            System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            System.out.println("Введите текст (для завершения — пустая строка):");
            StringBuilder sb = new StringBuilder();
            String line;
            while (!(line = scanner.nextLine()).isEmpty()) {
                sb.append(line).append("\n");
            }
            String plaintext = sb.toString().trim();

            if (plaintext.isEmpty()) {
                System.out.println(" Текст пуст\n");
                return;
            }

            System.out.print("Специальное слово (пароль): ");
            String specialWord = scanner.nextLine();
            if (specialWord.isEmpty()) {
                System.out.println(" Пароль не может быть пустым\n");
                return;
            }

            System.out.print("Имя выходного файла (Enter для авто): ");
            String outName = scanner.nextLine().trim();
            if (outName.isEmpty()) outName = "message_" + System.currentTimeMillis();
            String outFile = DATA_DIR + "/" + outName + ".enc";

            System.out.println("\n  Шифрование...");
            long start = System.currentTimeMillis();

            byte[] plaintextBytes = plaintext.getBytes("UTF-8");
            byte[] packageBytes = encryptPackage(plaintextBytes, specialWord,
                    senderKeys, recipientKeys);

            Files.write(Paths.get(outFile), packageBytes);

            long elapsed = System.currentTimeMillis() - start;

            System.out.println("    Зашифровано за " + elapsed + " мс");
            System.out.println("    Размер текста:    " + plaintextBytes.length + " байт");
            System.out.println("    Размер пакета:    " + packageBytes.length + " байт");
            System.out.println("    Сохранено в:      " + outFile);
            System.out.println("    Хеш специального слова (SHA-256): " + sha256Short(specialWord.getBytes("UTF-8")));
            System.out.println();

        } catch (Exception e) {
            System.out.println(" Ошибка: " + e.getMessage() + "\n");
        }
    }

    // ==================== ШИФРОВАНИЕ ФАЙЛА ====================

    private static void encryptFileToFile() {
        try {
            if (senderKeys == null || recipientKeys == null) {
                System.out.println("\n Сначала загрузите ключи (пункт 1)\n");
                return;
            }

            System.out.println("\n ШИФРОВАНИЕ ФАЙЛА");
            System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            System.out.print("Путь к исходному файлу: ");
            String inPath = scanner.nextLine().trim();
            if (!Files.exists(Paths.get(inPath))) {
                System.out.println(" Файл не найден\n");
                return;
            }

            System.out.print("Специальное слово (пароль): ");
            String specialWord = scanner.nextLine();
            if (specialWord.isEmpty()) {
                System.out.println(" Пароль не может быть пустым\n");
                return;
            }

            System.out.print("Имя выходного файла (Enter для авто): ");
            String outName = scanner.nextLine().trim();
            if (outName.isEmpty()) {
                String base = Paths.get(inPath).getFileName().toString();
                outName = base + ".enc";
            } else if (!outName.endsWith(".enc")) {
                outName += ".enc";
            }
            String outFile = DATA_DIR + "/" + outName;

            System.out.println("\n  Шифрование файла...");
            long start = System.currentTimeMillis();

            byte[] fileBytes = Files.readAllBytes(Paths.get(inPath));
            byte[] packageBytes = encryptPackage(fileBytes, specialWord,
                    senderKeys, recipientKeys);

            Files.write(Paths.get(outFile), packageBytes);

            long elapsed = System.currentTimeMillis() - start;
            String fileHash = sha256Short(fileBytes);

            System.out.println("    Зашифровано за " + elapsed + " мс");
            System.out.println("    Размер исходного:  " + fileBytes.length + " байт");
            System.out.println("    Размер пакета:     " + packageBytes.length + " байт");
            System.out.println("    Сохранено в:       " + outFile);
            System.out.println("    SHA-256 исходного: " + fileHash);
            System.out.println();

        } catch (Exception e) {
            System.out.println(" Ошибка: " + e.getMessage() + "\n");
        }
    }

    // ==================== РАСШИФРОВКА ====================

    private static void decryptFromFile() {
        try {
            if (recipientKeys == null) {
                System.out.println("\n Сначала загрузите ключи получателя (пункт 1)\n");
                return;
            }

            System.out.println("\n РАСШИФРОВКА ФАЙЛА");
            System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Список файлов
            File dir = new File(DATA_DIR);
            File[] files = dir.listFiles((d, n) -> n.endsWith(".enc"));

            if (files == null || files.length == 0) {
                System.out.println("   Нет зашифрованных файлов в папке " + DATA_DIR + "\n");
                return;
            }

            System.out.println("   Доступные файлы:");
            for (int i = 0; i < files.length; i++) {
                System.out.println("   [" + (i + 1) + "] " + files[i].getName() +
                        " (" + files[i].length() + " байт)");
            }

            System.out.print("\n   Выберите номер (или введите полный путь): ");
            String input = scanner.nextLine().trim();

            String inPath;
            try {
                int idx = Integer.parseInt(input) - 1;
                if (idx < 0 || idx >= files.length) throw new NumberFormatException();
                inPath = files[idx].getAbsolutePath();
            } catch (NumberFormatException e) {
                inPath = input;
            }

            if (!Files.exists(Paths.get(inPath))) {
                System.out.println(" Файл не найден\n");
                return;
            }

            System.out.print("Специальное слово (пароль): ");
            String specialWord = scanner.nextLine();

            System.out.print("Имя выходного файла (Enter для авто): ");
            String outName = scanner.nextLine().trim();
            if (outName.isEmpty()) {
                String base = Paths.get(inPath).getFileName().toString();
                outName = base.replace(".enc", "") + ".dec";
            }
            String outFile = DATA_DIR + "/" + outName;

            System.out.println("\n  Расшифровка...");
            long start = System.currentTimeMillis();

            byte[] packageBytes = Files.readAllBytes(Paths.get(inPath));
            DecryptionResult result = decryptPackage(packageBytes, specialWord,
                    recipientKeys.getPrivate());

            Files.write(Paths.get(outFile), result.data);

            long elapsed = System.currentTimeMillis() - start;

            System.out.println("    Расшифровано за " + elapsed + " мс");
            System.out.println("    Размер пакета:    " + packageBytes.length + " байт");
            System.out.println("    Размер данных:    " + result.data.length + " байт");
            System.out.println("    Сохранено в:      " + outFile);
            System.out.println("    SHA-256 данных:   " + sha256Short(result.data));
            System.out.println("    ЭЦП отправителя:  " + (result.signatureValid ? "✅ ДЕЙСТВИТЕЛЬНА" : "❌ НЕДЕЙСТВИТЕЛЬНА"));
            System.out.println();

            // Если это текст — показать превью
            if (isTextFile(result.data)) {
                System.out.println("    Превью расшифрованного текста:");
                System.out.println("   ─────────────────────────────────────────");
                String preview = new String(result.data, "UTF-8");
                if (preview.length() > 500) preview = preview.substring(0, 500) + "...";
                for (String l : preview.split("\n")) {
                    System.out.println("   │ " + l);
                }
                System.out.println("   ─────────────────────────────────────────\n");
            }

        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("\n Ошибка: Неверное специальное слово или файл повреждён!");
            System.out.println("   AES-GCM обнаружил несоответствие тега аутентификации.\n");
        } catch (Exception e) {
            System.out.println("\n Ошибка: " + e.getMessage() + "\n");
        }
    }

    // ==================== ИНФОРМАЦИЯ О ФАЙЛЕ ====================

    private static void showFileInfo() {
        try {
            System.out.println("\n  ИНФОРМАЦИЯ О ЗАШИФРОВАННОМ ФАЙЛЕ");
            System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            File dir = new File(DATA_DIR);
            File[] files = dir.listFiles((d, n) -> n.endsWith(".enc"));

            if (files == null || files.length == 0) {
                System.out.println("   Нет файлов\n");
                return;
            }

            for (int i = 0; i < files.length; i++) {
                System.out.println("   [" + (i + 1) + "] " + files[i].getName());
            }

            System.out.print("\n   Выберите номер: ");
            int idx = Integer.parseInt(scanner.nextLine().trim()) - 1;
            if (idx < 0 || idx >= files.length) {
                System.out.println(" Неверный номер\n");
                return;
            }

            byte[] data = Files.readAllBytes(files[idx].toPath());
            PackageInfo info = parsePackageInfo(data);

            System.out.println("\n    Структура пакета:");
            System.out.println("      Версия формата:    " + info.version);
            System.out.println("      Размер соли:       " + info.salt.length + " байт");
            System.out.println("      Размер IV:         " + info.iv.length + " байт");
            System.out.println("      RSA-ключ (wrap):   " + info.wrappedKeyLen + " байт");
            System.out.println("      Шифротекст:        " + info.ciphertextLen + " байт");
            System.out.println("      Публичный ключ:    " + info.senderPubKeyLen + " байт");
            System.out.println();
            System.out.println("      Криптография:");
            System.out.println("      KDF:               PBKDF2WithHmacSHA256 (100000 итераций)");
            System.out.println("      Шифрование:        AES-256-GCM (128-bit auth tag)");
            System.out.println("      Передача ключа:    RSA-2048-OAEP");
            System.out.println("      Подпись:           SHA256withRSA");
            System.out.println();
            System.out.println("      Хеш-суммы:");
            System.out.println("      SHA-256 файла:     " + sha256Short(data));
            System.out.println("      SHA-256 соли:      " + sha256Short(info.salt));
            System.out.println("      SHA-256 публ.ключа:" + sha256Short(info.senderPubKey));
            System.out.println();

        } catch (Exception e) {
            System.out.println(" Ошибка: " + e.getMessage() + "\n");
        }
    }

    // ==================== КРИПТОГРАФИЧЕСКОЕ ЯДРО ====================

    /**
     * Шифрует данные и формирует пакет формата HCRP
     */
    private static byte[] encryptPackage(byte[] data, String specialWord,
                                         KeyPair sender, KeyPair recipient) throws Exception {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(salt);
        random.nextBytes(iv);

        // Уровень 1: деривация ключа
        SecretKey aesKey = deriveKey(specialWord, salt);

        // Уровень 3: подпись
        byte[] signature = signData(data, sender.getPrivate());

        // Уровень 2: шифрование
        byte[] payload = concatenate(data, signature);
        byte[] ciphertext = encryptAES(payload, aesKey, iv);

        // Уровень 3: обёртка ключа
        byte[] wrappedKey = wrapAesKey(aesKey, recipient.getPublic());

        // Формирование пакета
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(MAGIC);
        out.write(VERSION);
        writeBytes(out, salt);
        writeBytes(out, iv);
        writeBytes(out, wrappedKey);
        writeBytes(out, ciphertext);
        writeBytes(out, sender.getPublic().getEncoded());

        return out.toByteArray();
    }

    /**
     * Расшифровывает пакет
     */
    private static DecryptionResult decryptPackage(byte[] packageBytes,
                                                   String specialWord, PrivateKey recipientPriv) throws Exception {

        ByteArrayInputStream in = new ByteArrayInputStream(packageBytes);

        // Проверка сигнатуры
        byte[] magic = new byte[4];
        in.read(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Неверный формат файла (нет сигнатуры HCRP)");
        }

        int version = in.read();
        if (version != VERSION) {
            throw new IOException("Неподдерживаемая версия формата: " + version);
        }

        byte[] salt = readBytes(in);
        byte[] iv = readBytes(in);
        byte[] wrappedKey = readBytes(in);
        byte[] ciphertext = readBytes(in);
        byte[] senderPubKeyBytes = readBytes(in);

        // Восстановление открытого ключа отправителя
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey senderPub = kf.generatePublic(new X509EncodedKeySpec(senderPubKeyBytes));

        // Расшифровка AES-ключа
        SecretKey aesKey = unwrapAesKey(wrappedKey, recipientPriv);

        // Расшифровка данных
        byte[] payload = decryptAES(ciphertext, aesKey, iv);

        // Разделение: последние 256 байт — подпись (RSA-2048)
        int sigLen = 256;
        byte[] data = Arrays.copyOfRange(payload, 0, payload.length - sigLen);
        byte[] signature = Arrays.copyOfRange(payload, payload.length - sigLen, payload.length);

        // Проверка подписи
        boolean sigValid = verifySignature(data, signature, senderPub);

        return new DecryptionResult(data, sigValid);
    }

    /**
     * Парсит пакет для показа информации (без расшифровки)
     */
    private static PackageInfo parsePackageInfo(byte[] packageBytes) throws Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(packageBytes);

        byte[] magic = new byte[4];
        in.read(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new IOException("Неверный формат");

        PackageInfo info = new PackageInfo();
        info.version = in.read();
        info.salt = readBytes(in);
        info.iv = readBytes(in);
        byte[] wk = readBytes(in);
        info.wrappedKeyLen = wk.length;
        byte[] ct = readBytes(in);
        info.ciphertextLen = ct.length;
        info.senderPubKey = readBytes(in);
        info.senderPubKeyLen = info.senderPubKey.length;

        return info;
    }

    // ==================== КРИПТО-ФУНКЦИИ ====================

    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        return new SecretKeySpec(f.generateSecret(spec).getEncoded(), "AES");
    }

    private static byte[] encryptAES(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }

    private static byte[] decryptAES(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }

    private static byte[] wrapAesKey(SecretKey key, PublicKey pub) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.WRAP_MODE, pub);
        return c.wrap(key);
    }

    private static SecretKey unwrapAesKey(byte[] wrapped, PrivateKey priv) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.UNWRAP_MODE, priv);
        return (SecretKey) c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }

    private static byte[] signData(byte[] data, PrivateKey priv) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(priv);
        s.update(data);
        return s.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] sig, PublicKey pub) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pub);
        s.update(data);
        return s.verify(sig);
    }

    // ==================== СОХРАНЕНИЕ/ЗАГРУЗКА КЛЮЧЕЙ ====================

    private static void savePublicKey(PublicKey key, String path) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(key.getEncoded());
        Files.write(Paths.get(path), b64.getBytes("UTF-8"));
    }

    private static PublicKey loadPublicKey(String path) throws Exception {
        String b64 = new String(Files.readAllBytes(Paths.get(path)), "UTF-8").trim();
        byte[] decoded = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    }

    private static void savePrivateKey(PrivateKey key, String path, String password) throws Exception {
        // Шифруем закрытый ключ паролем через AES
        byte[] keyBytes = key.getEncoded();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);

        SecretKey aesKey = deriveKey(password, salt);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] encrypted = c.doFinal(keyBytes);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(salt);
        out.write(iv);
        out.write(encrypted);

        String b64 = Base64.getEncoder().encodeToString(out.toByteArray());
        Files.write(Paths.get(path), b64.getBytes("UTF-8"));
    }

    private static PrivateKey loadPrivateKey(String path, String password) throws Exception {
        String b64 = new String(Files.readAllBytes(Paths.get(path)), "UTF-8").trim();
        byte[] blob = Base64.getDecoder().decode(b64);

        byte[] salt = Arrays.copyOfRange(blob, 0, 16);
        byte[] iv = Arrays.copyOfRange(blob, 16, 28);
        byte[] encrypted = Arrays.copyOfRange(blob, 28, blob.length);

        SecretKey aesKey = deriveKey(password, salt);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] keyBytes = c.doFinal(encrypted);

        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // ==================== УТИЛИТЫ ====================

    private static void writeBytes(ByteArrayOutputStream out, byte[] data) throws IOException {
        if (data.length <= 255) {
            out.write(data.length);
        } else if (data.length <= 65535) {
            out.write(0); // маркер 2-байтовой длины
            out.write((data.length >> 8) & 0xFF);
            out.write(data.length & 0xFF);
        } else {
            out.write(0);
            out.write(0);
            out.write((data.length >> 24) & 0xFF);
            out.write((data.length >> 16) & 0xFF);
            out.write((data.length >> 8) & 0xFF);
            out.write(data.length & 0xFF);
        }
        out.write(data);
    }

    private static byte[] readBytes(InputStream in) throws IOException {
        int b1 = in.read();
        int len;
        if (b1 == 0) {
            int b2 = in.read();
            int b3 = in.read();
            if (b3 == -1) {
                // 4-байтовая длина
                int b4 = in.read();
                len = (b2 << 24) | (b3 << 16) | (b4 << 8) | in.read();
            } else {
                len = (b2 << 8) | b3;
            }
        } else {
            len = b1;
        }

        byte[] data = new byte[len];
        int read = 0;
        while (read < len) {
            int r = in.read(data, read, len - read);
            if (r == -1) throw new IOException("Неожиданный конец файла");
            read += r;
        }
        return data;
    }

    private static byte[] concatenate(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static String sha256Short(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02X", hash[i]));
            }
            return sb.toString() + "...";
        } catch (Exception e) {
            return "error";
        }
    }

    private static boolean isTextFile(byte[] data) {
        if (data.length == 0) return false;
        int checkLen = Math.min(data.length, 512);
        for (int i = 0; i < checkLen; i++) {
            byte b = data[i];
            if (b == 9 || b == 10 || b == 13) continue; // tab, LF, CR
            if (b < 32 || b > 126) {
                // Проверяем UTF-8
                if ((b & 0x80) == 0) return false;
            }
        }
        return true;
    }

    // ==================== ВСПОМОГАТЕЛЬНЫЕ КЛАССЫ ====================

    private static class DecryptionResult {
        byte[] data;
        boolean signatureValid;
        DecryptionResult(byte[] d, boolean v) { data = d; signatureValid = v; }
    }

    private static class PackageInfo {
        int version;
        byte[] salt, iv;
        int wrappedKeyLen, ciphertextLen, senderPubKeyLen;
        byte[] senderPubKey;
    }
}