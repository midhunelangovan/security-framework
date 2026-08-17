package io.kals.security.aspect;

import io.kals.security.service.ValidationService;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;

@Slf4j
@Aspect
@Component
public class PermissionAspect {

    private final ValidationService validationService;
    @Value("${spring.application.code}")
    private String applicationCode;

    public PermissionAspect(ValidationService validationService) {
        this.validationService = validationService;
    }

    @Before("@annotation(IsAdmin)")
    public void isAdminValidation(JoinPoint joinPoint, IsAdmin isAdmin)
            throws NoSuchFieldException, IllegalAccessException {
        Object target = joinPoint.getTarget();
        String resourceName = resolvePlaceHolder(target);
        String permission = applicationCode + "/" + resourceName + "/read";
        validationService.validatePermission(permission);
    }

    @Before("@annotation(IsReader)")
    public void isReaderValidation(JoinPoint joinPoint, IsReader isReader)
            throws NoSuchFieldException, IllegalAccessException {
        Object target = joinPoint.getTarget();
        String resourceName = resolvePlaceHolder(target);
        String permission = applicationCode + "/" + resourceName + "/read";
        validationService.validatePermission(permission);
    }

    @Before("@annotation(IsEditor)")
    public void isEditorValidation(JoinPoint joinPoint, IsEditor isEditor)
            throws NoSuchFieldException, IllegalAccessException {
        Object target = joinPoint.getTarget();
        String resourceName = resolvePlaceHolder(target);
        String permission = applicationCode + "/" + resourceName + "/read";
        validationService.validatePermission(permission);
    }

    private String resolvePlaceHolder(Object target) throws NoSuchFieldException, IllegalAccessException {
        Field field = target.getClass().getDeclaredField("resourceName");
        return field.get(target).toString();
    }

}
