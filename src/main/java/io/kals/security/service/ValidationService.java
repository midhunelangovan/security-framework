package io.kals.security.service;

import io.kals.security.utils.UserUtil;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.ResourceAccessException;

import java.util.Objects;

@Service
public class ValidationService {

    public void validatePermission(String permission) {
        if (!Objects.requireNonNull(UserUtil.getUserRoleFromSpringContext()).equalsIgnoreCase("SUPER_ADMIN") && !hasPermissionAuthority(permission)) {
            throw new ResourceAccessException("invalid access");
        }
    }

    private boolean hasPermissionAuthority(String permission) {
        return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().anyMatch(grantedAuthority ->
                grantedAuthority.getAuthority().equalsIgnoreCase(permission)
        );
    }

}
