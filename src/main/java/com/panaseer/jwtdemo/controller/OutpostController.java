package com.panaseer.jwtdemo.controller;


import com.panaseer.jwtdemo.model.RsaKeyProperties;
import com.panaseer.jwtdemo.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/outpost")
@EnableConfigurationProperties(RsaKeyProperties.class)
public class OutpostController {
    private static final Logger LOG = LoggerFactory.getLogger(OutpostController.class);

    private final TokenService tokenService;

    public OutpostController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/auth/token")
    public String token(Authentication authentication, @RequestHeader(name = "Outpost-Id") String outpostId ) {
        LOG.debug("Token requested for user {}", authentication.getName());
        LOG.debug("outpostId: {}", outpostId);
        String token = tokenService.generateToken(authentication);
        LOG.debug("Token granted: {}", token);
        return token;
    }

    @GetMapping("/commands")
    public String commands(final Principal principal, final JwtAuthenticationToken auth) {
        LOG.debug("CLAIMS: {}", auth.getToken().getClaims());
        return "[{command}]";
    }

    @PostMapping("/heartbeat")
    public String heartbeat(Principal principal) {
        LOG.debug("/heartbeat received from: {}", principal);
        return "Heartbeat received " + principal.getName();
    }

}
