package com.myclass.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class JWTAuthenticationFilter extends BasicAuthenticationFilter{

	private UserDetailsService userDetailsService;
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, 
			UserDetailsService userDetailsService) {
		super(authenticationManager);
		this.userDetailsService = userDetailsService;
	}

	// CHỨC NĂNG KIỂM TRA TOKEN
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
			FilterChain chain)
			throws IOException, ServletException {
		
		//B1: Lấy token từ header
		String tokenHeader = request.getHeader("Authorization");
		
		//B2: Loại bỏ tiền tố 'Bearer ' để lấy JWT token
		if(tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
			try {
				String token = tokenHeader.replace("Bearer ", "");
				
				//B3: Giải mã token lấy email gán trong subject của token
				String email = Jwts
						.parser()
						.setSigningKey("ALO123")
						.parseClaimsJws(token)
						.getBody()
						.getSubject();
				
				//B4: Sử dụng email vừa lấy => truy vấn db để lấy thông tin user
				UserDetails userDetails = userDetailsService.loadUserByUsername(email);
				
				Authentication authentication = 
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				
				//B5: Set thông tin user vào SecurityContext
				SecurityContextHolder.getContext().setAuthentication(authentication);
				
			}
			catch (Exception e) {
				response.sendError(400, "Token không đúng định dạng!");
			}
		}
		
		// Cho phép request đi tiếp (vào filter tiếp theo hoặc controller)
		chain.doFilter(request, response);
	}
}
