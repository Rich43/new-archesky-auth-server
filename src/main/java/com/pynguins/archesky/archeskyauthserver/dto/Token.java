package com.pynguins.archesky.archeskyauthserver.dto;

import java.util.List;

public class Token {
    private final String username;
    private final String firstName;
    private final String lastName;
    private final String fullName;
    private final String email;
    private final List<Role> roles;

    public Token(String username, String firstName, String lastName, String fullName, String email, List<Role> roles) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.fullName = fullName;
        this.email = email;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getFullName() {
        return fullName;
    }

    public String getEmail() {
        return email;
    }

    public List<Role> getRoles() {
        return List.copyOf(roles);
    }
}
