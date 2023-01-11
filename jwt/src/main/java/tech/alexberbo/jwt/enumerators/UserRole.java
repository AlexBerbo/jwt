package tech.alexberbo.jwt.enumerators;

import static tech.alexberbo.jwt.constants.Authority.*;

public enum UserRole {
    ROLE_USER(USER_AUTHORITIES),
    ROLE_HR(HR_AUTHORITIES),
    ROLE_MANAGER(MANAGER_AUTHORITIES),
    ROLE_ADMIN(ADMIN_AUTHORITIES),
    ROLE_SUPER_ADMIN(SUPER_ADMIN_AUTHORITIES);

    private String[] authorities;

    UserRole(String... authorities) {
        this.authorities = authorities;
    }
    public String[] getAuthorities() {
        return authorities;
    }
}
