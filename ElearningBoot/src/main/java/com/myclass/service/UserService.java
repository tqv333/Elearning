package com.myclass.service;

import java.util.List;

import com.myclass.dto.UserDto;
import com.myclass.entity.User;

public interface UserService {
	List<User> getAll();
	User getById(int id);
	User getByEmail(String email);
	void add(User role);
	void update(User role);
	void delete(int id);
	List<UserDto> getAllDto();
	void changePassword(User user);
}
