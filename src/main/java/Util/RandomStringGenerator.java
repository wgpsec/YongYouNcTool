package Util;

import java.util.Random;

public class RandomStringGenerator {

    private static final String CHAR_SET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String LETTER_SET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final Random random = new Random();

    public static String generateRandomString(int length) {
        if (length <= 0) {
            return "";
        }

        StringBuilder result = new StringBuilder(length);

        // 为第一个字符选择一个字母
        int randomIndex = random.nextInt(LETTER_SET.length());
        result.append(LETTER_SET.charAt(randomIndex));

        // 为剩余的字符选择随机字符
        for (int i = 1; i < length; i++) {
            randomIndex = random.nextInt(CHAR_SET.length());
            result.append(CHAR_SET.charAt(randomIndex));
        }

        return result.toString();
    }

}