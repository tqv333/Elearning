package com.myclass.controller;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.myclass.dto.LoginDto;
import com.myclass.entity.User;
import com.myclass.service.UserService;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
@RequestMapping("api/user")
public class UserController {
	
	@Autowired
	private UserService userService;
	
	@GetMapping("")
	public Object get() {
		
		try {
			// Lấy ra thông tin user lưu trữ trong SecurityContext
			Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
			// Ép kiểu về UserDetails
			UserDetails userDetails = (UserDetails) principal;
			// Lấy ra email
			String email = userDetails.getUsername();
			
			// Lấy ra thông tin user để trả về cho client
			User user = userService.getByEmail(email);
			return new ResponseEntity<User>(user, HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<HttpStatus>(HttpStatus.BAD_REQUEST);
		}
	}
}
