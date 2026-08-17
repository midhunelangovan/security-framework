package io.kals.security.utils;

import io.kals.security.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Utility class for fetching details of the currently authenticated user.
 * Currently returns mock data and should be updated to integrate with Spring Security.
 */
@Component
public class UserUtil {

    public static User getUser() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            return null;
        }

        Object details = authentication.getDetails();

        if (details instanceof User user) {
            return user;
        }

        return null;
    }


    /**
     * Gets the username of the current user.
     *
     * @return the username
     */
    public static String getUserName() {
        User user = getUser();
        if (user != null ) {
            return user.getUserName();
        }
        return "";
    }

    /**
     * Gets the user ID of the current user.
     *
     * @return the user ID
     */
    public static Long getUserId() {
        User user = getUser();
        if (user != null) {
            return user.getUserId().longValue();
        }
        return null;
    }

    /**
     * Gets the email address of the current user.
     *
     * @return the email address
     */
    public static String getUserEmail() {
        User user = getUser();
        if (user != null) {
            return user.getUserName();
        }
        return "";
    }

    public static String getUserRoleFromSpringContext() {
        User user = getUser();
        if (user != null) {
            return user.getUserRole();
        }
        return null;
    }

}
