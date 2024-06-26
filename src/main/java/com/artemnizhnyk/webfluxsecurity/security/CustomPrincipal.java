package com.artemnizhnyk.webfluxsecurity.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.Principal;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class CustomPrincipal implements Principal {
    private Long id;
    private String name;
}
