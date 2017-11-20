package com.hello.security.social;

import java.io.IOException;
import java.net.URI;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.social.UserIdSource;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionData;
import org.springframework.social.connect.ConnectionKey;
import org.springframework.social.connect.ConnectionRepository;
import org.springframework.social.connect.UserProfile;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.connect.support.OAuth2ConnectionFactory;
import org.springframework.social.oauth2.AccessGrant;
import org.springframework.social.security.SocialAuthenticationException;
import org.springframework.social.security.SocialAuthenticationFailureHandler;
import org.springframework.social.security.SocialAuthenticationRedirectException;
import org.springframework.social.security.SocialAuthenticationServiceLocator;
import org.springframework.social.security.SocialAuthenticationToken;
import org.springframework.social.security.SocialUserDetails;
import org.springframework.social.security.provider.SocialAuthenticationService;
import org.springframework.social.support.URIBuilder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.hello.model.Role;
import com.hello.model.User;
import com.hello.security.AppUserDetailsService;
import com.hello.security.AuthenticationTokenFilter;

@Component
public class FacebookTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	@Value("${facebook.app.access_token}")
	private String access_token;

	  @Value("${com.hello.token.header}")
	  private String tokenHeader;
	
	
	private static final String providerId = "facebook";

	private SocialAuthenticationServiceLocator authServiceLocator;

	private UserIdSource userIdSource;

	private UsersConnectionRepository usersConnectionRepository;

	@Autowired
	private AppUserDetailsService service;

	private static final Logger logger = LoggerFactory.getLogger(FacebookTokenAuthenticationFilter.class);
	
	private SimpleUrlAuthenticationFailureHandler delegateAuthenticationFailureHandler;

	public FacebookTokenAuthenticationFilter(AuthenticationManager authManager, UserIdSource userIdSource,
			UsersConnectionRepository usersConnectionRepository,
			SocialAuthenticationServiceLocator authServiceLocator) {
		super("/");
		setAuthenticationManager(authManager);
		this.userIdSource = userIdSource;
		this.usersConnectionRepository = usersConnectionRepository;
		this.authServiceLocator = authServiceLocator;
		this.delegateAuthenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler();
		super.setAuthenticationFailureHandler(
				new SocialAuthenticationFailureHandler(delegateAuthenticationFailureHandler));
		SimpleUrlAuthenticationSuccessHandler sas = new SimpleUrlAuthenticationSuccessHandler();
		sas.setRedirectStrategy(new  NoRedirectStrategy());//TODO May need to redirect 
		super.setAuthenticationSuccessHandler(sas);
	}

	public UsersConnectionRepository getUsersConnectionRepository() {
		return usersConnectionRepository;
	}

	public SocialAuthenticationServiceLocator getAuthServiceLocator() {
		return authServiceLocator;
	}

	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		logger.info("Attempt Authentication Starting");
		Authentication auth = null;
		Set<String> authProviders = authServiceLocator.registeredAuthenticationProviderIds();
		if (!authProviders.isEmpty() && authProviders.contains(providerId)) {
			SocialAuthenticationService<?> authService = authServiceLocator.getAuthenticationService(providerId);
			auth = attemptAuthService(authService, request, response);
			if (auth == null) {
				throw new AuthenticationServiceException("authentication failed");
			}
		}
		return auth;
	}

	
	
	@Override
public void doFilter(javax.servlet.ServletRequest req, javax.servlet.ServletResponse res, javax.servlet.FilterChain chain) throws IOException, ServletException {
		
		//TODO Need to clean up this logic
		RequestMatcher myMatcher = new AntPathRequestMatcher("/register");
		RequestMatcher myMatcher1 = new AntPathRequestMatcher("/oauth/token");
		RequestMatcher myMatcher2 = new AntPathRequestMatcher("/favicon.ico");
		RequestMatcher myMatcher3 = new AntPathRequestMatcher("/api/auth");
		RequestMatcher myMatcher4 = new AntPathRequestMatcher("/user");
		RequestMatcher myMatcher5 = new AntPathRequestMatcher("/user");

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (myMatcher.matches((HttpServletRequest) req) || myMatcher1.matches((HttpServletRequest) req)
				|| myMatcher2.matches((HttpServletRequest) req) || myMatcher3.matches((HttpServletRequest) req)
				|| myMatcher4.matches((HttpServletRequest) req) || myMatcher5.matches((HttpServletRequest) req)) {
			logger.info("Antmatcher so going to bypass");
    		chain.doFilter(req, res);
    	}
    	else if(auth != null && auth.getPrincipal() != null){
			logger.info("Auth is here so going to bypass");
			chain.doFilter(req, res);
		}
		else {
			logger.info("Everything else must be Authenticated");
			super.doFilter(req, res, chain);
		}
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		logger.info("Successfully Authenticated");
		chain.doFilter(request, response);
	}

	@Deprecated
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return true;
	}

	protected Connection<?> addConnection(SocialAuthenticationService<?> authService, String userId,
			ConnectionData data) {
		HashSet<String> userIdSet = new HashSet<String>();
		userIdSet.add(data.getProviderUserId());
		Set<String> connectedUserIds = usersConnectionRepository.findUserIdsConnectedTo(data.getProviderId(),
				userIdSet);
		if (connectedUserIds.contains(userId)) {
			// already connected
			return null;
		} else if (!authService.getConnectionCardinality().isMultiUserId() && !connectedUserIds.isEmpty()) {
			return null;
		}

		ConnectionRepository repo = usersConnectionRepository.createConnectionRepository(userId);

		if (!authService.getConnectionCardinality().isMultiProviderUserId()) {
			List<Connection<?>> connections = repo.findConnections(data.getProviderId());
			if (!connections.isEmpty()) {
				// TODO maybe throw an exception to allow UI feedback?
				return null;
			}
		}

		// add new connection
		Connection<?> connection = authService.getConnectionFactory().createConnection(data);
		connection.sync();
		repo.addConnection(connection);
		return connection;
	}

	private Authentication attemptAuthService(final SocialAuthenticationService<?> authService,
			final HttpServletRequest request, HttpServletResponse response)
					throws SocialAuthenticationRedirectException, AuthenticationException {
		String input_token = extractHeaderToken(request);
		
		if (input_token == null) {
			
			logger.info("No token in the request");
			throw new SocialAuthenticationException("No token in the request");
		}
		URIBuilder builder = URIBuilder.fromUri(String.format("%s/debug_token", "https://graph.facebook.com"));
		builder.queryParam("access_token", access_token);
		builder.queryParam("input_token", input_token);
		URI uri = builder.build();
		RestTemplate restTemplate = new RestTemplate();

		JsonNode resp = null;
		try {
			resp = restTemplate.getForObject(uri, JsonNode.class);
		} catch (HttpClientErrorException e) {
			System.out.println("Error validating token");
			throw new SocialAuthenticationException("Error validating token");
		}
		Boolean isValid = resp.path("data").findValue("is_valid").asBoolean();
		if (!isValid){
			logger.info("token is not valid");
			throw new SocialAuthenticationException("Token is not valid");
		}
		
		AccessGrant accessGrant = new AccessGrant(input_token, null, null,
				resp.path("data").findValue("expires_at").longValue());

		Connection<?> connection = ((OAuth2ConnectionFactory<?>) authService.getConnectionFactory())
				.createConnection(accessGrant);
		SocialAuthenticationToken token = new SocialAuthenticationToken(connection, null);
		Assert.notNull(token.getConnection());

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !auth.isAuthenticated()) {
			return doAuthentication(authService, request, token);
		} else {
			addConnection(authService, request, token);
			return null;
		}
	}

	private void addConnection(final SocialAuthenticationService<?> authService, HttpServletRequest request,
			SocialAuthenticationToken token) {
		// already authenticated - add connection instead
		String userId = userIdSource.getUserId();
		Object principal = token.getPrincipal();
		if (userId == null || !(principal instanceof ConnectionData))
			return;

		addConnection(authService, userId, (ConnectionData) principal);

	}

	private Authentication doAuthentication(SocialAuthenticationService<?> authService, HttpServletRequest request,
			SocialAuthenticationToken token) {
		try {
			if (!authService.getConnectionCardinality().isAuthenticatePossible())
			{
				return null;
			}	
			token.setDetails(authenticationDetailsSource.buildDetails(request));
			Authentication success=null;
			success = getAuthenticationManager().authenticate(token);
			Assert.isInstanceOf(SocialUserDetails.class, success.getPrincipal(), "unexpected principle type");
			updateConnections(authService, token, success);
			return success;
		} catch (BadCredentialsException e) {
			
			User registration = createUserForRegistration(token.getConnection());
			User registered;
			try {
				registered = service.registerUser(registration);
			} catch (Exception e1) {
				e1.printStackTrace();
				throw new SocialAuthenticationException("An email address was found from the database." + e1);
			}
			ConnectionRepository repo = usersConnectionRepository.createConnectionRepository(registered.getEmail());
			repo.addConnection(token.getConnection());
			Authentication success = getAuthenticationManager().authenticate(token);
			return success;

		}
	}

	private void updateConnections(SocialAuthenticationService<?> authService, SocialAuthenticationToken token,
			Authentication success) {

		String userId = ((SocialUserDetails) success.getPrincipal()).getUserId();
		Connection<?> connection = token.getConnection();
		ConnectionRepository repo = getUsersConnectionRepository().createConnectionRepository(userId);
		repo.updateConnection(connection);

	}

	private User createUserForRegistration(Connection<?> connection) {
		if (connection != null) {
			UserProfile socialMediaProfile = connection.fetchUserProfile();
			User user = new User();
			if (socialMediaProfile.getUsername() != null) {
				user.setUsername(socialMediaProfile.getUsername());
			} else {
				user.setUsername(socialMediaProfile.getEmail());
			}
			user.grantAuthority(Role.ROLE_USER);
			user.setEmail(socialMediaProfile.getEmail());
			user.setFirstName(socialMediaProfile.getFirstName());
			user.setLastName(socialMediaProfile.getLastName());
			ConnectionKey providerKey = connection.getKey();
			user.setSignInProvider(SocialMediaService.valueOf(providerKey.getProviderId().toUpperCase()));
			return user;

		}
		return null;
	}
	
	
	protected String extractHeaderToken(HttpServletRequest request) {
			String token = request.getHeader(tokenHeader);
			logger.info("authHeaderValue Token found" + token);
			return token;
	}

}