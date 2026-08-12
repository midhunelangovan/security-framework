package io.kals.security.aspect;

import io.kals.security.service.AuthorizationService;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class PermissionAspect {

    private final AuthorizationService authorizationService;
    @Value("${spring.application.code}")
    private String applicationCode;

    public PermissionAspect(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Before("@annotation(IsAdmin)")
    public void isAdminValidation(IsAdmin isAdmin) {
        String resourceName = isAdmin.resourceName();
        String permission = applicationCode + "/" + resourceName + "/read";
        authorizationService.validatePermission(permission);
    }

    @Before("@annotation(IsReader)")
    public void isReaderValidation(IsReader isReader) {
        String resourceName = isReader.resourceName();
        String permission = applicationCode + "/" + resourceName + "/read";
        authorizationService.validatePermission(permission);
    }

    @Before("@annotation(IsEditor=)")
    public void isEditorValidation(IsEditor isEditor) {
        String resourceName = isEditor.resourceName();
        String permission = applicationCode + "/" + resourceName + "/read";
        authorizationService.validatePermission(permission);
    }

}
