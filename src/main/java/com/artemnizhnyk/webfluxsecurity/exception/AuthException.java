package com.artemnizhnyk.webfluxsecurity.exception;

public class AuthException extends ApiException {
    public AuthException(String message, String errorCode) {
        super(message, errorCode);
    }
}
