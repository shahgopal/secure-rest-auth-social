package com.hello.security.social;


import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.social.security.SocialUserDetails;
import org.springframework.social.security.SocialUserDetailsService;
import org.springframework.stereotype.Service;

import com.hello.model.User;
import com.hello.security.UserRepository;

@Service
public class FacebookUserDetailsService implements SocialUserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(FacebookTokenAuthenticationFilter.class);

	@Autowired
	private UserRepository repository;

	
	@Override
	public SocialUserDetails loadUserByUserId(String userId) throws UsernameNotFoundException, DataAccessException {
		logger.debug("Loading user by user id: {}", userId);

		Optional<User> user = repository.findByUsername(userId);
		logger.debug("Found user: {}", user);

		if (user == null || !user.isPresent()) {
			throw new UsernameNotFoundException("No user found with username: " + userId);
		}
		
		User facebookUser =  user.get();

		User principal = new User();
		principal.setEmail(facebookUser.getEmail());
		principal.setPassword(facebookUser.getPassword());
		principal.setFirstName(facebookUser.getFirstName());
		principal.setUsername((facebookUser.getId().toString()));
		principal.setLastName(facebookUser.getLastName());
		principal.setSignInProvider(SocialMediaService.FACEBOOK);
		principal.setRoles(facebookUser.getRoles());

		logger.debug("Found user details: {}", principal);

		return principal;
	}
	
	
	
}