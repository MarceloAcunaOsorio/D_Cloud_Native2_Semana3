package com.example.Backend.Exceptions;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;

public class JwtAuthenticationException extends AuthenticationCredentialsNotFoundException{
    
    //private static final long serialVersionUID = 2;

    public JwtAuthenticationException(String message){
        super(message);
    }
}
