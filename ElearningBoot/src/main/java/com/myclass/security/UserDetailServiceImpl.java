package com.myclass.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.myclass.entity.User;
import com.myclass.repository.UserRepositoy;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

	@Autowired
	private UserRepositoy userRepositoy;
	
	@Override
	public UserDetails loadUserByUsername(String email) 
			throws UsernameNotFoundException {
		
		// Truy vấn db để lấy thông tin user
		User user = userRepositoy.findByEmail(email);
		if(user == null) throw new UsernameNotFoundException("Không tìm thấy!");
		// JOIN đến bảng Role để lấy roleName
		String roleName = user.getRole().getName();
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(roleName));
		
		// Lưu thông tin user vào trong CustomUserDetail để Security quản lý
		CustomUserDetail userDetail = 
				new CustomUserDetail(email, user.getPassword(), authorities);
		
		return userDetail;
	}

}
