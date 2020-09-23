package com.myclass.controller;

import java.io.File;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("api/file")
public class FileController {
	
	// Inject đường dẫn thư mục upload từ file application.properties
	@Value("${file.upload-dir}")
	private String uploadFolder;
	
	@Value("${file.upload-dir-return}")
	private String pathReturn;

	@PostMapping("upload")
	public Object upload(@RequestBody MultipartFile file) {
		try {
			// Lấy ra đường dẫn thư mục chứa dự án
			String rootPath = System.getProperty("user.dir");
			System.out.println(rootPath);
			// Đường dẫn thư mục chứa hình
			String folderPath = rootPath + uploadFolder;
			System.out.println(folderPath);
			
			// Kiểm tra xem thư mục tồn tại chưa
			File dir = new File(folderPath);
			if(!dir.exists()) {
				dir.mkdir(); // Tạo thư mục upload
			}
			
			// Đường dẫn file
			File filePath = new File(folderPath + file.getOriginalFilename());
			
			System.out.println(filePath);
			
			// Lưu file
			file.transferTo(filePath);
			
			String pathResult = pathReturn + file.getOriginalFilename();
			return new ResponseEntity<String>(pathResult, HttpStatus.OK);
		}
		catch (Exception e) {
			return new ResponseEntity<HttpStatus>(HttpStatus.BAD_REQUEST);
		}
	}
}
