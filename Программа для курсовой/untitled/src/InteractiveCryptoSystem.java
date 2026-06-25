import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Интерактивная многоуровневая криптосистема
 * Курсовой проект: AES-256-GCM + RSA-2048 + PBKDF2
 */
public class InteractiveCryptoSystem {

    // Состояние системы (хранится между операциями)
    private static KeyPair senderKeyPair = null;
    private static KeyPair recipientKeyPair = null;
    private static byte[] lastCiphertext = null;
    private static byte[] lastWrappedKey = null;
    private static byte[] lastSalt = null;
    private static byte[] lastIV = null;
    private static String lastSpecialWord = null;

    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║  ИНТЕРАКТИВНАЯ ГИБРИДНАЯ КРИПТОСИСТЕМА                  ║");
        System.out.println("║  AES-256-GCM + RSA-2048 + PBKDF2                        ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝\n");

        boolean running = true;
        while (running) {
            showMainMenu();
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    generateKeys();
                    break;
                case "2":
                    encryptMessage();
                    break;
                case "3":
                    decryptMessage();
                    break;
                case "4":
                    showPackageInfo();
                    break;
                case "5":
                    testIntegrity();
                    break;
                case "0":
                    running = false;
                    System.out.println("\n Завершение работы. До свидания!");
                    break;
                default:
                    System.out.println("❌ Неверный выбор. Попробуйте снова.\n");
            }
        }
        scanner.close();
    }

    // ==================== ГЛАВНОЕ МЕНЮ ====================

    private static void showMainMenu() {
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println(" ГЛАВНОЕ МЕНЮ:");
        System.out.println("   [1]  Сгенерировать RSA-ключи (отправитель + получатель)");
        System.out.println("   [2]  Зашифровать сообщение");
        System.out.println("   [3]  Расшифровать сообщение");
        System.out.println("   [4]  Показать информацию о последнем пакете");
        System.out.println("   [5]  Тест целостности (попытка подделки)");
        System.out.println("   [0]  Выход");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.print("Ваш выбор: ");
    }

    // ==================== ГЕНЕРАЦИЯ КЛЮЧЕЙ ====================

    private static void generateKeys() {
        try {
            System.out.println("\n Генерация RSA-2048 ключей...");
            System.out.print("   Размер ключа (2048 рекомендуется): ");
            String keySizeStr = scanner.nextLine().trim();
            int keySize = keySizeStr.isEmpty() ? 2048 : Integer.parseInt(keySizeStr);

            System.out.println("    Генерация (может занять несколько секунд)...");
            KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
            rsaGen.initialize(keySize);

            senderKeyPair = rsaGen.generateKeyPair();
            recipientKeyPair = rsaGen.generateKeyPair();

            System.out.println("    Ключи отправителя сгенерированы");
            System.out.println("    Ключи получателя сгенерированы");
            System.out.println("   ️  Открытые ключи доступны для шифрования");
            System.out.println("    Закрытые ключи хранятся в памяти (для демонстрации)\n");

        } catch (Exception e) {
            System.out.println("    Ошибка генерации ключей: " + e.getMessage() + "\n");
        }
    }

    // ==================== ШИФРОВАНИЕ ====================

    private static void encryptMessage() {
        try {
            if (senderKeyPair == null || recipientKeyPair == null) {
                System.out.println("    Сначала сгенерируйте ключи (пункт 1)\n");
                return;
            }

            System.out.println("\n ШИФРОВАНИЕ СООБЩЕНИЯ");
            System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Ввод текста
            System.out.print("Введите сообщение для шифрования: ");
            String plaintext = scanner.nextLine();
            if (plaintext.isEmpty()) {
                System.out.println("    Сообщение не может быть пустым\n");
                return;
            }

            // Ввод специального слова
            System.out.print("Введите специальное слово (пароль): ");
            String specialWord = scanner.nextLine();
            if (specialWord.isEmpty()) {
                System.out.println("    Специальное слово не может быть пустым\n");
                return;
            }

            System.out.println("\n  Процесс шифрования:");

            // Шаг 1: Генерация случайных параметров
            SecureRandom random = new SecureRandom();
            lastSalt = new byte[16];
            lastIV = new byte[12];
            random.nextBytes(lastSalt);
            random.nextBytes(lastIV);
            System.out.println("   [1/5]  Сгенерированы Salt и IV");

            // Шаг 2: Деривация ключа (Уровень 1)
            System.out.println("   [2/5]  Деривация AES-ключа из специального слова (PBKDF2)...");
            SecretKey aesKey = deriveKeyFromPassword(specialWord, lastSalt);
            lastSpecialWord = specialWord; // Сохраняем для демонстрации
            System.out.println("   [2/5]  AES-256 ключ получен");

            // Шаг 3: Электронная подпись (Уровень 3)
            System.out.println("   [3/5]  Создание электронной подписи (SHA256withRSA)...");
            byte[] signature = signData(plaintext.getBytes("UTF-8"), senderKeyPair.getPrivate());
            System.out.println("   [3/5]  ЭЦП создана (" + signature.length + " байт)");

            // Шаг 4: Шифрование текста + подписи (Уровень 2)
            System.out.println("   [4/5]  AES-256-GCM шифрование...");
            byte[] payload = concatenate(plaintext.getBytes("UTF-8"), signature);
            lastCiphertext = encryptAES(payload, aesKey, lastIV);
            System.out.println("   [4/5]  Текст зашифрован (" + lastCiphertext.length + " байт)");

            // Шаг 5: RSA-обёртка AES-ключа (Уровень 3)
            System.out.println("   [5/5]  RSA-OAEP обёртка AES-ключа...");
            lastWrappedKey = wrapAesKey(aesKey, recipientKeyPair.getPublic());
            System.out.println("   [5/5]  AES-ключ зашифрован RSA (" + lastWrappedKey.length + " байт)");

            System.out.println("\n ШИФРОВАНИЕ ЗАВЕРШЕНО УСПЕШНО!");
            System.out.println("   ️  Пакет готов. Используйте пункт 3 для расшифровки.\n");

        } catch (Exception e) {
            System.out.println("    Ошибка шифрования: " + e.getMessage() + "\n");
        }
    }

    // ==================== РАСШИФРОВКА ====================

    private static void decryptMessage() {
        try {
            if (lastCiphertext == null) {
                System.out.println("    Нет зашифрованных данных. Сначала зашифруйте сообщение (пункт 2)\n");
                return;
            }

            System.out.println("\n РАСШИФРОВКА СООБЩЕНИЯ");
            System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            System.out.print("Введите специальное слово (пароль): ");
            String specialWord = scanner.nextLine();

            System.out.println("\n  Процесс расшифровки:");

            // Шаг 1: Расшифровка AES-ключа (Уровень 3)
            System.out.println("   [1/4]  Расшифровка AES-ключа закрытым ключом получателя (RSA-OAEP)...");
            SecretKey aesKey = unwrapAesKey(lastWrappedKey, recipientKeyPair.getPrivate());
            System.out.println("   [1/4]  AES-ключ восстановлен");

            // Шаг 2: Расшифровка текста (Уровень 2)
            System.out.println("   [2/4]  AES-256-GCM расшифровка...");
            byte[] decryptedPayload = decryptAES(lastCiphertext, aesKey, lastIV);
            System.out.println("   [2/4]  Данные расшифрованы");

            // Разделение текста и подписи
            int signatureLength = 256; // RSA-2048
            byte[] decryptedTextBytes = Arrays.copyOfRange(decryptedPayload, 0,
                    decryptedPayload.length - signatureLength);
            byte[] recoveredSignature = Arrays.copyOfRange(decryptedPayload,
                    decryptedPayload.length - signatureLength, decryptedPayload.length);

            String decryptedText = new String(decryptedTextBytes, "UTF-8");

            // Шаг 3: Проверка ЭЦП (Уровень 3)
            System.out.println("   [3/4]  Проверка электронной подписи (SHA256withRSA)...");
            boolean isValid = verifySignature(decryptedTextBytes, recoveredSignature,
                    senderKeyPair.getPublic());

            if (isValid) {
                System.out.println("   [3/4]  Подпись действительна");
            } else {
                System.out.println("   [3/4]  Подпись НЕДЕЙСТВИТЕЛЬНА!");
            }

            // Шаг 4: Проверка специального слова
            System.out.println("   [4/4]  Верификация специального слова...");
            boolean wordCorrect = specialWord.equals(lastSpecialWord);
            if (wordCorrect) {
                System.out.println("   [4/4]  Специальное слово верное");
            } else {
                System.out.println("   [4/4]   Специальное слово неверное (но данные расшифрованы)");
            }

            // Итог
            System.out.println("\n╔══════════════════════════════════════════════════════════╗");
            System.out.println("║  РЕЗУЛЬТАТ РАСШИФРОВКИ                                   ║");
            System.out.println("╚══════════════════════════════════════════════════════════╝");
            System.out.println("   Текст: " + decryptedText);
            System.out.println("   Целостность (ЭЦП): " + (isValid ? " ДА" : " НЕТ"));
            System.out.println("   Пароль верный: " + (wordCorrect ? " ДА" : " НЕТ"));
            System.out.println();

            if (!isValid) {
                System.out.println("     ВНИМАНИЕ: Данные могли быть подделаны!\n");
            } else {
                System.out.println("    Данные подлинные и не изменялись.\n");
            }

        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("    Ошибка: Данные повреждены или неверный ключ!");
            System.out.println("     AES-GCM обнаружил изменение в шифротексте.\n");
        } catch (Exception e) {
            System.out.println("    Ошибка расшифровки: " + e.getMessage() + "\n");
        }
    }

    // ==================== ИНФОРМАЦИЯ О ПАКЕТЕ ====================

    private static void showPackageInfo() {
        if (lastCiphertext == null) {
            System.out.println("    Нет данных для отображения. Сначала зашифруйте сообщение.\n");
            return;
        }

        System.out.println("\n ИНФОРМАЦИЯ О ПОСЛЕДНЕМ ПАКЕТЕ");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("   Salt (16 байт):     " + bytesToHex(lastSalt));
        System.out.println("   IV (12 байт):       " + bytesToHex(lastIV));
        System.out.println("   Wrapped AES-key:    " + truncateHex(bytesToHex(lastWrappedKey), 48));
        System.out.println("   Ciphertext:         " + truncateHex(bytesToHex(lastCiphertext), 48));
        System.out.println();
        System.out.println("   Размер пакета:      " +
                (lastSalt.length + lastIV.length + lastWrappedKey.length + lastCiphertext.length) + " байт");
        System.out.println("   Алгоритмы:          PBKDF2 + AES-256-GCM + RSA-2048-OAEP");
        System.out.println("   Подпись:            SHA256withRSA\n");
    }

    // ==================== ТЕСТ ЦЕЛОСТНОСТИ ====================

    private static void testIntegrity() {
        if (lastCiphertext == null) {
            System.out.println("    Нет данных для теста. Сначала зашифруйте сообщение.\n");
            return;
        }

        System.out.println("\n ТЕСТ ЦЕЛОСТНОСТИ (Атака на шифротекст)");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("   Симуляция: злоумышленник изменил 1 байт в шифротексте");

        // Копируем и изменяем 1 байт
        byte[] tamperedCiphertext = lastCiphertext.clone();
        tamperedCiphertext[10] ^= 0xFF; // Инвертируем байт

        System.out.println("   Исходный байт [10]:  " + String.format("%02X", lastCiphertext[10]));
        System.out.println("   Изменённый байт [10]: " + String.format("%02X", tamperedCiphertext[10]));
        System.out.println();

        System.out.println("   Попытка расшифровки подделанных данных...");

        try {
            SecretKey aesKey = unwrapAesKey(lastWrappedKey, recipientKeyPair.getPrivate());
            byte[] decrypted = decryptAES(tamperedCiphertext, aesKey, lastIV);
            System.out.println("    ОШИБКА: Расшифровка прошла (это не должно было произойти!)");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("    УСПЕХ: AES-GCM обнаружил подделку!");
            System.out.println("     Auth Tag не совпал — данные отклонены");
            System.out.println("   ️  Это доказывает защиту от атак на целостность\n");
        } catch (Exception e) {
            System.out.println("    Другая ошибка: " + e.getMessage() + "\n");
        }
    }

    // ==================== КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ ====================

    private static SecretKey deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static byte[] encryptAES(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(data);
    }

    private static byte[] decryptAES(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(ciphertext);
    }

    private static byte[] wrapAesKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(aesKey);
    }

    private static SecretKey unwrapAesKey(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    private static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    // ==================== УТИЛИТЫ ====================

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static String truncateHex(String hex, int maxLen) {
        if (hex.length() <= maxLen) return hex;
        return hex.substring(0, maxLen) + "... [" + hex.length() + " символов]";
    }

    private static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}