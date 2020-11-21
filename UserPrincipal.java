package com.home.app.ws.fullstackappws.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.home.app.ws.fullstackappws.io.entity.AuthorityEntity;
import com.home.app.ws.fullstackappws.io.entity.RoleEntity;
import com.home.app.ws.fullstackappws.io.entity.UserEntity;


public class UserPrincipal implements UserDetails {
	private static final long serialVersionUID = -7395350407640401509L;
	
	private UserEntity userEntity;
	private String userId;
	public UserPrincipal(UserEntity userEntity) {
		this.userEntity = userEntity;
		this.userId = userId;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		List<AuthorityEntity> authorityEntity = new ArrayList<>();
		//Get user roles
		Collection<RoleEntity> roles = this.userEntity.getRoles();
		if(roles == null) return authorities;
		roles.forEach((role)->{
			authorities.add(new SimpleGrantedAuthority(role.getName()));
			authorityEntity.addAll(role.getAuthorities());
		});
		
		authorityEntity.forEach((authEnt)->{
			
			authorities.add(new SimpleGrantedAuthority(authEnt.getName()));
		});
		
		return authorities;
	}

	@Override
	public String getPassword() {
		return this.userEntity.getEncryptedPassword();
	}

	@Override
	public String getUsername() {
		return this.userEntity.getEmail();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		//for now EmailVerificationStatus is false all the time
		return true;
		//return this.userEntity.getEmailVerificationStatus();
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}
}
