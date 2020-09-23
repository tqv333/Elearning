package com.myclass.dto;

public class UserDto {
	private int id;
	private String email;
	private String fullname;
	private String phone;
	private String roleName;
	
	public UserDto() {}

	public UserDto(int id, String email, String fullname, String phone, String roleName) {
		super();
		this.id = id;
		this.email = email;
		this.fullname = fullname;
		this.phone = phone;
		this.roleName = roleName;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getFullname() {
		return fullname;
	}

	public void setFullname(String fullname) {
		this.fullname = fullname;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public String getRoleName() {
		return roleName;
	}

	public void setRoleName(String roleName) {
		this.roleName = roleName;
	}
}
