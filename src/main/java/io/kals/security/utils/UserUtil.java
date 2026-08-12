package io.kals.security.utils;

import org.springframework.stereotype.Component;

/**
 * Utility class for fetching details of the currently authenticated user.
 * Currently returns mock data and should be updated to integrate with Spring Security.
 */
@Component
public class UserUtil {


    /**
     * Gets the username of the current user.
     * @return the username
     */
    public static String getUserName() {
        return "systemuser@kal.io";
    }

    /**
     * Gets the user ID of the current user.
     * @return the user ID
     */
    public static Long getUserId() {
        return 1L;
    }

    /**
     * Gets the email address of the current user.
     * @return the email address
     */
    public static String getUserEmail() {
        return "systemuser@kal.io";
    }

    public static String getUserRoleFromSpringContext(){
        return "ROLE_ADMIN";
    }

}
