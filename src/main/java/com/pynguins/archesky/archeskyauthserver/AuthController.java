package com.pynguins.archesky.archeskyauthserver;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;

import static org.springframework.http.HttpStatus.FOUND;

@RestController
public class AuthController {
    @RequestMapping(value = "/", method = RequestMethod.GET)
    public ResponseEntity<String> index() throws URISyntaxException {
        return ResponseEntity.status(FOUND).location(new URI("/swagger-ui/")).build();
    }

    @RequestMapping(value = "/auth", method = RequestMethod.POST)
    public String auth() {
        return "authenticated";
    }
}
