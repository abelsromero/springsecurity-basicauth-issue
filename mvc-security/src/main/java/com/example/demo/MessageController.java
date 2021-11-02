package com.example.demo;

import java.time.LocalDateTime;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessageController {

	class Message {

		public String text;
		public LocalDateTime timestamp;
	}

	@GetMapping("/hello")
	Message hello() {
		Message message = new Message();
		message.text = "Hello!";
		message.timestamp = LocalDateTime.now();
		return message;
	}
}
