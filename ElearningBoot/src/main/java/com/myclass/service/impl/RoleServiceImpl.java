package com.myclass.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.myclass.entity.Role;
import com.myclass.repository.RoleRepository;
import com.myclass.service.RoleService;

@Service
public class RoleServiceImpl implements RoleService {
	
	@Autowired
	private RoleRepository roleRepository;

	@Override
	public List<Role> getAll() {
		return roleRepository.findAll();
	}

	@Override
	public Role getById(int id) {
		return roleRepository.findById(id).get();
	}

	@Override
	public void add(Role role) {
		roleRepository.save(role);
	}

	@Override
	public void update(Role role) {
		Role entity = roleRepository.findById(role.getId()).get();
		if(entity != null) {
			entity.setName(role.getName());
			entity.setDescription(role.getDescription());
			roleRepository.save(entity);
		}
	}

	@Override
	public void delete(int id) {
		roleRepository.deleteById(id);
	}
}
