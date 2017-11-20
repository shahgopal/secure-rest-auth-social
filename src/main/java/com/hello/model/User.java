package com.hello.model;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.social.security.SocialUser;
import org.springframework.social.security.SocialUserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.hello.security.social.SocialMediaService;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
//
@Entity
@Table(name = "app_user")
public class User  implements SocialUserDetails {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    @Column(name = "id")
//    private Long id;
//
//    @Column(name = "username")
//    private String username;
//
//    @Column(name = "password")
////    @JsonIgnore
//    private String password;
//
//    @Column(name = "first_name")
//    private String firstName;
//
//    @Column(name = "last_name")
//    private String lastName;
//
//    /**
//     * Roles are being eagerly loaded here because
//     * they are a fairly small collection of items for this example.
//     */
//    @ManyToMany(fetch = FetchType.EAGER)
//    @JoinTable(name = "user_role", joinColumns
//            = @JoinColumn(name = "user_id",
//            referencedColumnName = "id"),
//            inverseJoinColumns = @JoinColumn(name = "role_id",
//                    referencedColumnName = "id"))
//    private List<Role> roles;
//


//	public User(String username, String password, boolean enabled, boolean accountNonExpired,
//			boolean credentialsNonExpired, boolean accountNonLocked,
//			Collection<? extends GrantedAuthority> authorities) {
////      this.accountNonExpired = true;
////      this.accountNonLocked = true;
////      this.credentialsNonExpired = true;
////      this.enabled = true;
//		
//		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
//		// TODO Auto-generated constructor stub
//	}
//	public User(String username, String password, 
//			Collection<? extends GrantedAuthority> authorities) {
//		
//		super(username, password, true, true, true, true, authorities);
//		// TODO Auto-generated constructor stub
//	}
//	public User(String username, String password){ 
//		super(username, password, true, true, true, true, null);
//		// TODO Auto-generated constructor stub
//	}
//	public User() {
//	}

	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Id
    @GeneratedValue(strategy= GenerationType.SEQUENCE)
    private Long id;

	@Column(name = "username", unique=true)
    private String username;

	@Column(name = "password")    
    private String password;

	@Column(name = "first_name")
    private String firstName;

	@Column(name = "last_name")
    private String lastName;

	@Column(name = "email")
	private String email;

	@Enumerated(EnumType.STRING)
    @ElementCollection(fetch = FetchType.EAGER)
    private List<Role> roles;

	@Column(name = "account_non_expired")
	private boolean accountNonExpired; 
	@Column(name = "account_non_locked")
	private boolean accountNonLocked;
	@Column(name = "credentials_non_expired")
	private boolean credentialsNonExpired; 
	@Column(name = "enabled")
	private boolean enabled;

	
	@Column(name = "sign_in_provider", length = 20)
	private SocialMediaService signInProvider;

	  @Column(name = "last_password_reset")
	  private Date lastPasswordReset;

    public User() {
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }
    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }
    @Override
    public boolean isEnabled() {
        return enabled;
    }
    public void grantAuthority(Role authority) {
        if ( roles == null ) roles = new ArrayList<>();
        roles.add(authority);
    }
    @Override
    public List<GrantedAuthority> getAuthorities(){
        List<GrantedAuthority> authorities = new ArrayList<>();
        roles.forEach(role -> authorities.add(new SimpleGrantedAuthority(role.toString())));
        return authorities;
    }
    public List<Role> getRoles() {
        return roles;
    }
    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }
    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }
    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getFirstName() {
        return firstName;
    }
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }
    public String getLastName() {
        return lastName;
    }
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

	public SocialMediaService getSignInProvider() {
		return signInProvider;
	}

	public void setSignInProvider(SocialMediaService signInProvider) {
		this.signInProvider = signInProvider;
	}

	@Override
	public String toString() {
		return "User [id=" + id + ", username=" + username + ", password=" + password + ", firstName=" + firstName
				+ ", lastName=" + lastName + ", email=" + email + ", roles=" + roles + ", accountNonExpired="
				+ accountNonExpired + ", accountNonLocked=" + accountNonLocked + ", credentialsNonExpired="
				+ credentialsNonExpired + ", enabled=" + enabled + "]";
	}
	@Override
	public String getUserId() {
		// TODO Auto-generated method stub
		return null;
	}
	
	  public Date getLastPasswordReset() {
		    return this.lastPasswordReset;
		  }

		  public void setLastPasswordReset(Date lastPasswordReset) {
		    this.lastPasswordReset = lastPasswordReset;
		  }
	
	

}