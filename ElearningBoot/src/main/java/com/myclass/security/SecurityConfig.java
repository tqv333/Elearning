package com.myclass.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() 
			throws Exception {
		return super.authenticationManager();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
		.userDetailsService(userDetailsService)
		.passwordEncoder(new BCryptPasswordEncoder());
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.cors();
		
		http
			.csrf().disable()
			.antMatcher("/api/**") // Những url bắt đầu bằng /api/ sẽ được kiểm tra
			.authorizeRequests()
			.antMatchers("/api/auth", "/api/auth/login") // Nếu gặp url là /api/user/login
			.permitAll() // bỏ qua phần kiểm tra đăng nhập
			.antMatchers("/api/role**")
			.hasAnyRole("ADMIN")
			.antMatchers("/api/user**")
			.hasAnyRole("ADMIN", "TEACHER")
			.anyRequest() // Tất cả những url còn lại đều phải 
			.authenticated(); // đăng nhập trước mới được phép truy cập
		
		http.addFilter(new JWTAuthenticationFilter(authenticationManager(), userDetailsService));
		// Cấu hình không lưu trữ bất kỳ thông nào vào trong session (Ko sử dụng session)
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring()
		.antMatchers("/v2/api-docs",
			"/configuration/ui",
			"/swagger-resources/**",
			"/configuration/security",
			"/swagger-ui.html**",
			"/webjars/**",
			"/upload/**");
	}
}
