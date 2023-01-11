package tech.alexberbo.jwt.constants;

public class SecurityConstants {
    public static final long EXPIRATION_TIME = 432000000;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String ALEXBERBO_RS = "alexberbo, RS";
    public static final String ALEXBERBO_ADMINISTRATION = "User Management Portal";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to login to see this page";
    public static final String ACCESS_DENIED_MESSAGE = "Access denied, you do not have the permission to see this page";
    public static final String OPTIONS_HTTP_MESSAGE = "OPTIONS";
    public static final String[] PUBLIC_URLS = { "/user/login", "/user/register", "/user/resetpassword/**", "/user/image/**"};
    public static final String[] NON_PUBLIC_URLS = { "/user/welcome", "/user/edit", "/user/delete", "/user/create" };
}
