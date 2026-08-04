package io.kals.security.utils;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class AuthUtils {

    public static String encryptPassword(String password){
        // password -> $23$323wjhvfhwbvrvb (Encrypts the password text)
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(password);
    }

    public static boolean validatePassword(String userRequestPassword, String validUserPassword) {
        //validUserPassword is encrypted
        //userRequestPassword is in text format
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.matches(userRequestPassword, validUserPassword);
    }
}
