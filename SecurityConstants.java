package com.home.app.ws.fullstackappws.security;

import com.home.app.ws.fullstackappws.SpringApplicationContext;

public class SecurityConstants {
	public static final long EXPIRATION_TIME = 864000000; // 10 days
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String SIGN_UP_URL = "/users";
    public static final String H2_CONSOLE = "/h2-console/**";
   public static final String TOKEN_SECRET = "jf9i4jgu83nfl0jfu57ejf7"; // Lets put it to application.properties file
    
	/*
	 * public static String getTokenSecret() { AppProperties appProp =
	 * (AppProperties) SpringApplicationContext.getBean("AppProperties"); return
	 * appProp.getTokenSecret(); }
	 */
}
