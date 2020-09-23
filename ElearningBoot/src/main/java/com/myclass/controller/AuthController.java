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
import org.springframework.web.bind.annotation.CrossOrigin;
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
@RequestMapping("api/auth")
public class AuthController {

	@Autowired
	private UserService userService;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@PostMapping("")
	public Object post(@RequestBody User user) {
		try {
			userService.add(user);
			return new ResponseEntity<HttpStatus>(HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<HttpStatus>(HttpStatus.BAD_REQUEST);
		}
	}
	
	@PostMapping("login")
	public Object login(@RequestBody LoginDto loginDto) {
		try {
			// Kiá»ƒm tra Ä‘Äƒng nháº­p (email vÃ  máº­t kháº©u)
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword()));
			
			// Náº¿u khÃ´ng xáº£y ra exception tá»©c lÃ  thÃ´ng tin há»£p lá»‡
	        // Set thÃ´ng tin authentication vÃ o Security Context
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			Date dateNow = new Date();
			// Táº¡o token
			String token = Jwts.builder()
					.setSubject(loginDto.getEmail()) // LÆ°u email
					.setIssuedAt(dateNow) // NgÃ y táº¡o
					.setExpiration(new Date(dateNow.getTime() + 864000000L)) // NgÃ y háº¿t háº¡n
					.signWith(SignatureAlgorithm.HS512, "ALO123") // MÃ£ hÃ³a thÃ´ng tin
					.compact();
			
			// Tráº£ vá»� token cho ngÆ°á»�i dÃ¹ng.
			return new ResponseEntity<String>(token, HttpStatus.OK);
		}
		catch (BadCredentialsException e) {
			// Náº¿u khÃ´ng xáº£y ra exception tá»©c lÃ  thÃ´ng tin khÃ´ng há»£p lá»‡
			return new ResponseEntity<String>("Sai thÃ´ng tin Ä‘Äƒng nháº­p!", HttpStatus.BAD_REQUEST);
		}
		catch (Exception e) {
			return new ResponseEntity<HttpStatus>(HttpStatus.BAD_REQUEST);
		}
	}
}
