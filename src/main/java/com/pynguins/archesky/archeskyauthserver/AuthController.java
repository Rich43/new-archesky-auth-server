package com.pynguins.archesky.archeskyauthserver;

import com.auth0.jwk.JwkException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.pynguins.archesky.archeskyauthserver.dto.Role;
import com.pynguins.archesky.archeskyauthserver.dto.Token;
import com.pynguins.archesky.archeskyauthserver.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static org.springframework.http.HttpStatus.FOUND;

@RestController
public class AuthController {
    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public ResponseEntity<String> index() throws URISyntaxException {
        return ResponseEntity.status(FOUND).location(new URI("/swagger-ui/")).build();
    }

    @RequestMapping(value = "/auth", method = RequestMethod.GET)
    public Token checkToken(@RequestParam String token, @RequestHeader String hostname) throws MalformedURLException, AuthenticationException, JwkException {
        final DecodedJWT validatedToken = tokenService.validateToken(token, hostname);
        final List<Role> roleList = tokenService.createRoleList(validatedToken);
        return new Token(
                validatedToken.getClaim("preferred_username").asString(),
                validatedToken.getClaim("given_name").asString(),
                validatedToken.getClaim("family_name").asString(),
                validatedToken.getClaim("name").asString(),
                validatedToken.getClaim("email").asString(),
                roleList
        );
    }
}
