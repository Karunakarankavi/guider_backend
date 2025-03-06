package com.guider.services;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.guider.entity.User;
import com.guider.repository.UserRepository;

@Service
public class CustomUsers implements UserDetailsService{
	
	private final UserRepository userRepository;
	public CustomUsers(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
	
	

	 @Override
	    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		  System.out.println("load user");
	        User user = userRepository.findByUsername(username)
	                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
	        
	        return org.springframework.security.core.userdetails.User.builder()
	                .username(user.getUsername())
	                .password(user.getPassword())
	                .roles(user.getRole().replace("ROLE_", "")) // Spring Security requires role without "ROLE_" prefix
	                .build();
	    }

}
