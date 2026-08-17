package io.kals.security.configuration;

import io.jsonwebtoken.security.Keys;
import io.kals.security.model.User;
import io.kals.security.service.PermissionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.*;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final PermissionService permissionService;
    @Value("${auth.jwt.secret}")
    private String secretKey;

    public JwtAuthenticationFilter(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader("Kals-Authorization-Token");

        try {
            Claims claims = Jwts.parser().verifyWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8))).build().parseSignedClaims(token).getPayload();

            // validate expiry
            if (claims.getExpiration().before(new Date())) {
                response.sendError(HttpStatus.FORBIDDEN.value(), "Your session has expired. Please log in again.");
            }
            String username = claims.getSubject();
            Integer userId = (Integer) claims.get("userId");
            String userName = (String) claims.get("userName");
            String userRole = (String) claims.get("userRole");
            Boolean isActive = (Boolean) claims.get("isActive");
            ZonedDateTime lastLoginAt = (ZonedDateTime) claims.get("lastLoginAt");

            String userPermission = permissionService.getUserPermissions(Long.valueOf(userId));

            List<SimpleGrantedAuthority> authorities = new ArrayList<>();

            authorities.add(
                    new SimpleGrantedAuthority("ROLE_" + userRole)
            );
            if (!userPermission.isBlank()) {
                for (String permission : userPermission.split(",")) {
                    authorities.add(new SimpleGrantedAuthority(permission));
                }
            }

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            User user = User.builder()
                    .userId(userId)
                    .userName(userName)
                    .isActive(isActive)
                    .userRole(userRole)
                    .lastLoginAt(lastLoginAt)
                    .build();

            authentication.setDetails(user);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            response.sendError(HttpStatus.FORBIDDEN.value(), "Token has been altered or is not valid");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        return path.startsWith("/ping")
                || path.startsWith("/login")
                || path.startsWith("/forgot-" +
                "password")
                || path.startsWith("/reset-password");
    }

}
