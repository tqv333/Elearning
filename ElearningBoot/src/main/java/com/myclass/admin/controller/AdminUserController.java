package com.myclass.admin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.myclass.entity.User;
import com.myclass.service.RoleService;
import com.myclass.service.UserService;

@Controller
@RequestMapping("admin/user")
public class AdminUserController {

	@Autowired
	private UserService userService;
	
	@Autowired
	private RoleService roleService;
	
	@RequestMapping(value = "", method = RequestMethod.GET)
	public String index(Model model) {
		model.addAttribute("users", userService.getAllDto());
		return "user/index";
	}
	
	@RequestMapping(value = "add", method = RequestMethod.GET)
	public String add(Model model) {
		model.addAttribute("roles", roleService.getAll());
		model.addAttribute("user", new User());
		return "user/add";
	}
	
	@RequestMapping(value = "add", method = RequestMethod.POST)
	public String add(@ModelAttribute("user") User user, Model model) {
		userService.add(user);
		return "redirect:/admin/user";
	}
	
	@RequestMapping(value = "edit", method = RequestMethod.GET)
	public String edit(@RequestParam int id, Model model) {
		model.addAttribute("roles", roleService.getAll());
		model.addAttribute("user", userService.getById(id));
		return "user/edit";
	}
	
	@RequestMapping(value = "edit", method = RequestMethod.POST)
	public String edit(@ModelAttribute("user") User user, Model model) {
		userService.update(user);
		return "redirect:/admin/user";
	}
	
	@RequestMapping(value = "delete", method = RequestMethod.GET)
	public String delete(@RequestParam int id) {
		userService.delete(id);
		return "redirect:/admin/role";
	}
	
	@RequestMapping(value = "password", method = RequestMethod.GET)
	public String password(@RequestParam int id, Model model) {
		model.addAttribute("user", userService.getById(id));
		return "user/password";
	}
	
	@RequestMapping(value = "password", method = RequestMethod.POST)
	public String password(@ModelAttribute("user") User user, Model model) {
		userService.changePassword(user);
		return "redirect:/admin/user";
	}
}
