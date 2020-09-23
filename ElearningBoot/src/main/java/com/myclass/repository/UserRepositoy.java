package com.myclass.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.myclass.dto.UserDto;
import com.myclass.entity.User;

@Repository
public interface UserRepositoy extends JpaRepository<User, Integer>{

	User findByEmail(String email);
	
	List<User> findByEmailOrFullname(String email, String fullname);
	
	@Query("SELECT new com.myclass.dto.UserDto(u.id, u.email, u.fullname, u.phone, r.name) FROM User u JOIN u.role r")
	List<UserDto> getAll();
}
