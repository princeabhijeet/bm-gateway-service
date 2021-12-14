package com.prince.ms.gateway.config;

import java.util.ArrayList;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.prince.ms.gateway.exceptions.GatewayException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class LdapAuthenticationProvider implements AuthenticationProvider {
	
	@Autowired
	private Environment env;
	
	private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(LdapAuthenticationProvider.class);

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		Boolean isLdapAuthenticated = ldapAuthenticate(username, authentication.getCredentials().toString());
		if(isLdapAuthenticated) {
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, authentication.getCredentials().toString(), new ArrayList<>());
			log.info("LDAP Authentication - UsernamePasswordAuthenticationToken - {}", authenticationToken);
			log.info("LDAP Authentication - SUCCESS - Authentic user {}", username);
			return authenticationToken;
		}
		else {
			throw new GatewayException("Invalid User", HttpStatus.UNAUTHORIZED.value());
		}
	}
	
    @SuppressWarnings("rawtypes")
	public Boolean ldapAuthenticate(String username, String password) {
    	
    	log.error("LDAP Authentication - START - username {}", username);
    	Boolean isLdapAuthenticated = Boolean.FALSE;
    	
    	DirContext initialDirectoryContext = initialDirectoryContext();
    	String searchFilter = env.getProperty("ldap.search-filter").replace("?", username);
    	SearchControls searchControls = new SearchControls();
    	searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    	searchControls.setReturningAttributes(new String[] {"cn", "sn"});
    	SearchResult searchResult = null;
    	
    	try {
    		NamingEnumeration namingEnum = initialDirectoryContext.search(env.getProperty("ldap.user-dn"), searchFilter, searchControls);
    		initialDirectoryContext.close();
	    	
    		if(namingEnum.hasMore()) {
	    		searchResult = (SearchResult) namingEnum.next();
	    		String cn = searchResult.getAttributes().get("cn").toString();
	    		String sn = searchResult.getAttributes().get("sn").toString();
	    		String distinguishedName = searchResult.getNameInNamespace();
	    		log.info("LDAP Authentication - username VALIDATED - Search Filter {}", searchFilter);
	    		log.info("LDAP Authentication - username details fetched from LDAP server - CommonName[{}] | SurName[{}] | DistinguishedName[{}]", cn, sn, distinguishedName);
	    		
	    		log.info("LDAP Authentication - START - credential - distinguished name [{}]", distinguishedName);
	    		DirContext userPasswordDirectoryContext = userPasswordDirectoryContext(distinguishedName, password);
	    		userPasswordDirectoryContext.close();
	    		log.info("LDAP Authentication - credential VALIDATED - distinguished name [{}]", distinguishedName);
	    		isLdapAuthenticated = Boolean.TRUE;
	    		
	    	}
    		else {
    			log.error("LDAP Authentication - FAILED - Unauthentic User {}", username);
    			isLdapAuthenticated = Boolean.FALSE;
    		}
	    }
    	catch (NamingException e) {
			log.error("LDAP Authentication - FAILED - Unauthentic User {}", username);
			log.error("LDAP Authentication - EXCEPTION (NamingException) {}", e.getMessage());
			isLdapAuthenticated = Boolean.FALSE;
		}
    	return isLdapAuthenticated;
    }
    
    public DirContext initialDirectoryContext() {
    	DirContext initialDirectoryContext = null;
    	Properties properties = new Properties();
    	try {
	    	properties.put(Context.PROVIDER_URL, env.getProperty("ldap.url"));
	    	properties.put(Context.SECURITY_PRINCIPAL, env.getProperty("ldap.security-principal"));
	    	properties.put(Context.SECURITY_CREDENTIALS, env.getProperty("ldap.security-credential"));
	    	properties.put(Context.SECURITY_AUTHENTICATION, env.getProperty("ldap.security-authentication"));
	    	properties.put(Context.INITIAL_CONTEXT_FACTORY, env.getProperty("ldap.initial-context-factory"));
	    	initialDirectoryContext = new InitialDirContext(properties);
		} 
    	catch (NamingException e) {
			throw new GatewayException("LDAP - Invalid LDAP configuration in Gateway Config or LDAP Server not up", HttpStatus.UNAUTHORIZED.value());
		}
    	return initialDirectoryContext;
    }
    
    public DirContext userPasswordDirectoryContext(String securityPrincipalDistinguishedName, String credentialsUserPassword) {
    	DirContext userPasswordDirectoryContext = null;
    	Properties properties = new Properties();
    	try {
	    	properties.put(Context.PROVIDER_URL, env.getProperty("ldap.url"));
	    	properties.put(Context.SECURITY_PRINCIPAL, securityPrincipalDistinguishedName);												
	    	properties.put(Context.SECURITY_CREDENTIALS, credentialsUserPassword);
	    	properties.put(Context.INITIAL_CONTEXT_FACTORY, env.getProperty("ldap.initial-context-factory"));
	    	userPasswordDirectoryContext = new InitialDirContext(properties);
		}
    	catch (NamingException e) {
			throw new GatewayException("LDAP - Invalid Credentials", HttpStatus.UNAUTHORIZED.value());
		}
    	return userPasswordDirectoryContext;
    }


	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
    
}
