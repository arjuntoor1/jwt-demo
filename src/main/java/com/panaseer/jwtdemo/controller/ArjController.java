package com.panaseer.jwtdemo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/arj")
public class ArjController {
    private static final Logger LOG = LoggerFactory.getLogger(ArjController.class);

    @GetMapping("/hello")
    public String arjHello(Principal principal) {
        LOG.debug("/hello received from principal: {}", principal.getName());
        return "hello %s /arj/hello".formatted(principal.getName());
    }

}
