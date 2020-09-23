package com.myclass.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.myclass.entity.Category;
import com.myclass.repository.CategoryRepository;
import com.myclass.service.CategoryService;

@Service
public class CategoryServiceImpl implements CategoryService {
	
	@Autowired
	private CategoryRepository categoryRepository;

	@Override
	public List<Category> getAll() {
		return categoryRepository.findAll();
	}

	@Override
	public Category getById(int id) {
		return categoryRepository.findById(id).get();
	}

	@Override
	public void add(Category category) {
		categoryRepository.save(category);
	}

	@Override
	public void update(Category category) {
		Category entity = categoryRepository.findById(category.getId()).get();
		if(entity != null) {
			entity.setTitle(category.getTitle());
			entity.setIcon(category.getIcon());
			entity.setOrderIndex(category.getOrderIndex());
			categoryRepository.save(entity);
		}
	}

	@Override
	public void delete(int id) {
		categoryRepository.deleteById(id);
	}
}
