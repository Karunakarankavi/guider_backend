package com.guider.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CheckController {
	
	
    @PostMapping("/check")
	public String checkMethod() {
		return "security working fine";
	}
	

}
