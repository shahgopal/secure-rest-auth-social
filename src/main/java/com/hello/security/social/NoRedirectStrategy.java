package com.hello.security.social;


import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.RedirectStrategy;

public class NoRedirectStrategy implements RedirectStrategy {

	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
		
		System.out.println("NO REDIRECT");
		//No redirect
	}
}