package com.myclass.service;

import java.util.List;

import com.myclass.entity.Category;

public interface CategoryService {
	List<Category> getAll();
	Category getById(int id);
	void add(Category category);
	void update(Category category);
	void delete(int id);
}
