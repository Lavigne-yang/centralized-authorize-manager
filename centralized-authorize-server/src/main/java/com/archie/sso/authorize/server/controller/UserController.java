package com.archie.sso.authorize.server.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.archie.sso.authorize.server.service.UserService;

import lombok.RequiredArgsConstructor;

/**
 * @author lavyoung1325
 */
@RestController
@RequestMapping("/u")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;
    
    
    @PostMapping("/register")
    public ResponseEntity<Object> register() {

        ResponseEntity<String> body = ResponseEntity.ok().body("");


        return null;
    }
    
}
