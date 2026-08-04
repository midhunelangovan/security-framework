package io.kals.security.configuration;

import io.jsonwebtoken.security.Keys;
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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${auth.jwt.secret}")
    private String secretKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader("KALS-HEADER-TOKEN");

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
            Integer employeeId = (Integer) claims.get("employeeId");
            Boolean isActive = (Boolean) claims.get("isActive");
            ZonedDateTime lastLoginAt = (ZonedDateTime) claims.get("lastLoginAt");

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + userRole)));
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            Map<String, Object> authDetails = new HashMap<>();
            authDetails.put("userId", userId);
            authDetails.put("employeeId", employeeId);
            authDetails.put("userName", userName);
            authDetails.put("userRole", userRole);
            authDetails.put("isActive", isActive);
            authDetails.put("lastLoginAt", lastLoginAt);

            authentication.setDetails(authDetails);

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
