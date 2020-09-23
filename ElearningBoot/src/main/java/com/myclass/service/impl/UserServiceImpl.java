package com.myclass.service.impl;

import java.util.List;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.myclass.dto.UserDto;
import com.myclass.entity.User;
import com.myclass.repository.UserRepositoy;
import com.myclass.service.UserService;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private UserRepositoy userRepository;
	
	@Override
	public List<User> getAll() {
		return userRepository.findAll();
	}

	@Override
	public User getById(int id) {
		return userRepository.findById(id).get();
	}

	@Override
	public void add(User user) {
		
		// KIểm tra email tồn tại chưa
		User entity = userRepository.findByEmail(user.getEmail());
		if(entity == null) {
			// Max hóa mật khẩu
			String hashed = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt());
			// Sửa lại mật khẩu thành mật khẩu đã mã hóa
			user.setPassword(hashed);
			userRepository.save(user);
		}
	}

	@Override
	public void update(User user) {
		// Lấy thông tin hiện tại user đang lưu trong database
		User entity = userRepository.findById(user.getId()).get();
		
		// Cập nhật lại một số thông tin truyền từ view lên
		if(entity != null) {
			entity.setEmail(user.getEmail());
			entity.setFullname(user.getFullname());
			entity.setAvatar(user.getAvatar());
			entity.setPhone(user.getPhone());
			entity.setRoleId(user.getRoleId());
			userRepository.save(entity);
		}
	}

	@Override
	public void delete(int id) {
		userRepository.deleteById(id);
	}

	@Override
	public List<UserDto> getAllDto() {
		return userRepository.getAll();
	}

	@Override
	public void changePassword(User user) {
		// Lấy thông tin hiện tại user đang lưu trong database
		User entity = userRepository.findByEmail(user.getEmail());
		if(entity != null) {
			// Mã hóa mật khẩu
			String hashed = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt());
			// Cập nhật lại mật khẩu
			entity.setPassword(hashed);
		}
	}

	@Override
	public User getByEmail(String email) {
		return userRepository.findByEmail(email);
	}

}
