package com.pynguins.archesky.archeskyauthserver.service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.pynguins.archesky.archeskyauthserver.config.ApplicationProperties;
import com.pynguins.archesky.archeskyauthserver.dto.Role;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.*;

import static java.lang.String.format;

@Service
public class TokenService {
    private final ApplicationProperties applicationProperties;

    public TokenService(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    public DecodedJWT validateToken(String token, String domain) throws JwkException, AuthenticationException, MalformedURLException {
        final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        final DecodedJWT jwt = JWT.decode(token);
        final JwkProvider provider = new UrlJwkProvider(new URL(format(applicationProperties.getCertificateURL(), domain)));
        final Jwk jwk = provider.get(jwt.getKeyId());
        final Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
        algorithm.verify(jwt);
        if (!jwt.getIssuer().equals(format(applicationProperties.getIssuer(), domain))) {
            throw new AuthenticationException(
                    format(
                            "Token validation failed: Invalid issuer (Expected: '%s' but got '%s')",
                            format(applicationProperties.getIssuer(), domain),
                            jwt.getIssuer()
                    )
            );
        }
        if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
            throw new AuthenticationException(
                    format(
                            "Token validation failed: The token expired at %s",
                            sdf.format(jwt.getExpiresAt())
                    )
            );
        }
        return jwt;
    }

    @SuppressWarnings("unchecked")
    public List<Role> createRoleList(DecodedJWT validatedToken) {
        final List<Role> roleList = new ArrayList<>();
        final String realmAccess = "realm_access";
        if (validatedToken.getClaims().containsKey(realmAccess)) {
            for (Map.Entry<String, Object> role : validatedToken.getClaim(realmAccess).asMap().entrySet()) {
                roleList.add(new Role(realmAccess, ((ArrayList<String>) role.getValue())));
            }
        }
        final String resourceAccess = "resource_access";
        if (validatedToken.getClaims().containsKey(resourceAccess)) {
            for (Map.Entry<String, Object> role : validatedToken.getClaim(resourceAccess).asMap().entrySet()) {
                roleList.add(new Role(role.getKey(), ((LinkedHashMap<String, ArrayList<String>>) role.getValue()).get("roles")));
            }
        }
        return roleList;
    }
}
