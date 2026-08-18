package io.kals.security.model;

import lombok.*;

import java.time.ZonedDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    private Integer userId;

    private String userName;

    private String userRole;

    private Boolean isActive;

    private ZonedDateTime lastLoginAt;
}