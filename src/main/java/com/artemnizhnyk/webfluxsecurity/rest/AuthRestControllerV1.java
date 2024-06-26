package com.artemnizhnyk.webfluxsecurity.rest;

import com.artemnizhnyk.webfluxsecurity.service.UserService;
import com.artemnizhnyk.webfluxsecurity.dto.AuthRequestDto;
import com.artemnizhnyk.webfluxsecurity.dto.AuthResponseDto;
import com.artemnizhnyk.webfluxsecurity.dto.UserDto;
import com.artemnizhnyk.webfluxsecurity.entity.UserEntity;
import com.artemnizhnyk.webfluxsecurity.mapper.UserMapper;
import com.artemnizhnyk.webfluxsecurity.security.CustomPrincipal;
import com.artemnizhnyk.webfluxsecurity.security.SecurityService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@RestController
public class AuthRestControllerV1 {
    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto dto) {
        UserEntity entity = userMapper.map(dto);
        return userService.registerUser(entity)
                .map(userMapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto dto) {
        return securityService.authenticate(dto.getUsername(), dto.getPassword())
                .flatMap(tokenDetails -> Mono.just(
                        AuthResponseDto.builder()
                                .userId(tokenDetails.getUserId())
                                .token(tokenDetails.getToken())
                                .issuedAt(tokenDetails.getIssuedAt())
                                .expiresAt(tokenDetails.getExpiresAt())
                                .build()
                ));
    }

    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(Authentication authentication) {
        CustomPrincipal customPrincipal = (CustomPrincipal) authentication.getPrincipal();

        return userService.getUserById(customPrincipal.getId())
                .map(userMapper::map);
    }
}
