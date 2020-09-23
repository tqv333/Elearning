package com.myclass.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/home")
public class HomeController {

	@RequestMapping(value = "", method = RequestMethod.GET)
	public String index() {
		return "home/index";
	}
}
