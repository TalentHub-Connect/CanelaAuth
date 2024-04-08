package com.talenthub.auth.exception;

import lombok.Getter;

@Getter
public class ErrorKeycloakServiceException extends Exception{
    private final int statusCode;
    public ErrorKeycloakServiceException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }
}