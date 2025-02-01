package com.godea.authorization.services;

import com.godea.authorization.models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Service
public class JwtService {
    private static final String ROLE = "role";
    // 604800000 - одна неделя до истечения срока действия токена
    private static final long EXPIRATION_MS = 604800000;

    @Value("${token.signing}")
    private String secret;

    public String generate(User user) {
        Date date = new Date();

        return Jwts.builder()
                .signWith(getSecretKey(), Jwts.SIG.HS512)
                .subject(user.getUsername())
                .issuedAt(date)
                .expiration(new Date(date.getTime() + EXPIRATION_MS))
                .claim(ROLE, user.getAuthorities().stream().findFirst().get().getAuthority())
                .compact();
    }

    public boolean validate(String token) {
        try {
            parse(token);
            return true;
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        return false;
    }

    // Получаю payload из токена
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSecretKey() {
        byte[] encodeKey = Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(encodeKey);
    }
}
