package com.hello.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.hello.model.User;
import com.hello.security.AppUserDetailsService;

@RestController
public class RegistrationControllar {

	@Autowired
	AppUserDetailsService userDetailsService;
	private static final Logger logger = LoggerFactory.getLogger(RegistrationControllar.class);

	@CrossOrigin
	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<String> registerUser(@RequestBody User user) throws Exception {
		logger.info("Here is the information of User=" + user);
		User savedUser = userDetailsService.registerUser(user);
		return new ResponseEntity<>("Thank you for your Registraton successfully", HttpStatus.OK);
	}

}
