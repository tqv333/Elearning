package com.myclass.controller;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.myclass.entity.Role;
import com.myclass.service.RoleService;

@RestController
@RequestMapping("api/role")
public class RoleController {
	
	@Autowired
	private RoleService roleService;
	
	@RequestMapping(value = "", method = RequestMethod.GET)
	public Object index() {
		try {
			// Gọi service để lấy data
			List<Role> roles = roleService.getAll();
			// Trả data + httpstattus code về cho client
			return new ResponseEntity<List<Role>>(roles, HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<String>("Không lấy được được dữ liệu!", HttpStatus.BAD_REQUEST);
		}
	}
	
	@RequestMapping(value = "", method = RequestMethod.POST)
	public Object add(@RequestBody Role role) {
		try {
			// Gọi service thêm data
			roleService.add(role);
			// Trả data + httpstattus code về cho client
			return new ResponseEntity<String>("Thêm mới thành công!", HttpStatus.CREATED);
		}
		catch (Exception e) {
			return new ResponseEntity<String>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}
	
	@RequestMapping(value = "/{id}", method = RequestMethod.PUT)
	public Object put(@PathVariable int id, @RequestBody Role role) {
		try {
			// Gọi service thêm data
			role.setId(id);
			roleService.update(role);
			// Trả data + httpstattus code về cho client
			return new ResponseEntity<String>("Cập nhật thành công!", HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<String>("Cập nhật thất bại!", HttpStatus.BAD_REQUEST);
		}
	}
	
	@RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
	public Object put(@PathVariable int id) {
		try {
			// Gọi service xóa data
			roleService.delete(id);
			// Trả data + httpstattus code về cho client
			return new ResponseEntity<String>("Xóa thành công!", HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<String>("Xóa thất bại!", HttpStatus.BAD_REQUEST);
		}
	}
}
