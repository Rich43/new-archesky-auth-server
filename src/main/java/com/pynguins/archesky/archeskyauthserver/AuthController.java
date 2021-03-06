package com.pynguins.archesky.archeskyauthserver;

import com.auth0.jwk.JwkException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.pynguins.archesky.archeskyauthserver.dto.Role;
import com.pynguins.archesky.archeskyauthserver.dto.Token;
import com.pynguins.archesky.archeskyauthserver.service.TokenService;
import org.slf4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.AuthenticationException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.http.HttpStatus.FOUND;

@RestController
public class AuthController {
    private static class CheckTokenRequestBody {
        private final String token;
        private final String hostname;

        private CheckTokenRequestBody(String token, String hostname) {
            this.token = token;
            this.hostname = hostname;
        }

        public String getToken() {
            return token;
        }

        public String getHostname() {
            return hostname;
        }
    }

    private final TokenService tokenService;
    private final Logger log = getLogger(this.getClass());

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public ResponseEntity<String> index() throws URISyntaxException {
        return ResponseEntity.status(FOUND).location(new URI("/swagger-ui/")).build();
    }

    @RequestMapping(value = "/auth", method = RequestMethod.POST)
    public Token checkToken(@RequestBody CheckTokenRequestBody checkTokenRequestBody) throws MalformedURLException, AuthenticationException, JwkException {
        log.info("Checking token for hostname: {}", checkTokenRequestBody.getHostname());
        log.info("Token: {}", checkTokenRequestBody.getToken());
        final DecodedJWT validatedToken = tokenService.validateToken(
                checkTokenRequestBody.getToken(),
                checkTokenRequestBody.getHostname()
        );
        final List<Role> roleList = tokenService.createRoleList(validatedToken);
        final Token token = new Token(
                validatedToken.getClaim("preferred_username").asString(),
                validatedToken.getClaim("given_name").asString(),
                validatedToken.getClaim("family_name").asString(),
                validatedToken.getClaim("name").asString(),
                validatedToken.getClaim("email").asString(),
                roleList
        );
        log.info("Token validated: {}", token);
        return token;
    }
}
