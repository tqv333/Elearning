package com.myclass.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.myclass.entity.Category;
import com.myclass.service.CategoryService;

@RestController
@RequestMapping("api/category")
public class CategoryController {

	@Autowired
	private CategoryService categoryService;
	
	@GetMapping("")
	public Object get() {
		try {
			// Gọi service lấy danh sách category
			List<Category> categories = categoryService.getAll();
			// Trả kết quả về cho frontend
			return new ResponseEntity<List<Category>>(categories, HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<HttpStatus>(HttpStatus.BAD_REQUEST);
		}
	}
	
	@PostMapping("")
	public Object post(@RequestBody Category category) {
		try {
			// Gọi service thêm category
			categoryService.add(category);
			// Trả kết quả về cho frontend
			return new ResponseEntity<HttpStatus>(HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<HttpStatus>(HttpStatus.BAD_REQUEST);
		}
	}
}
