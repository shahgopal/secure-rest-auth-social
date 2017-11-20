package com.hello.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import com.hello.model.Role;
import com.hello.model.User;

public class AppUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userRepo;
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
		Optional<User> user = userRepo.findByUsername(s);
		if (user.isPresent()) {
			return user.get();
		} else {
			throw new UsernameNotFoundException(String.format("Username[%s] not found", s));
		}
	}

	public User findUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> user = userRepo.findByUsername(username);
		if (user.isPresent()) {
			return user.get();
		} else {
			throw new UsernameNotFoundException(String.format("Username[%s] not found", username));
		}
	}

	public User registerUser(User user) {
		System.out.println("passwordEncoder" + passwordEncoder + user.toString());
		if (user != null && user.getPassword() != null) {
			user.setPassword(passwordEncoder.encode(user.getPassword()));
		}
		user.grantAuthority(Role.ROLE_USER);
		return userRepo.save(user);

	}

	@Transactional // To successfully remove the date @Transactional annotation
					// must be added
	public boolean removeAuthenticatedUser() throws UsernameNotFoundException {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		User user = findUserByUsername(username);
		int del = userRepo.deleteUserById(user.getId());
		return del > 0;
	}
}