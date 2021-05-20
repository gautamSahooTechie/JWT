package com.gautam.jwt.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @RequestMapping(value = "/recommended")
    public String readingList(){
        return "Learning spring boot";
    }
}
