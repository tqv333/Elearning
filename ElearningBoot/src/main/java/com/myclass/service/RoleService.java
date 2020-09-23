package com.myclass.service;

import java.util.List;

import com.myclass.entity.Role;

public interface RoleService {
	List<Role> getAll();
	Role getById(int id);
	void add(Role role);
	void update(Role role);
	void delete(int id);
}
