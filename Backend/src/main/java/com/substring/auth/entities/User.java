package com.substring.auth.entities;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "users")
public class User implements Serializable, UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    private UUID id;
    @Column(name = "user_email",unique = true,length = 100,nullable = false)
    private String email;
    @Column(name = "user_name",length = 100,nullable = false)
    private String name;
    private String password;
    private String image;
    private boolean enable = true;
    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();
//    private String gender;
//    private Address address;


    @Enumerated(EnumType.STRING)
    private Provider provider= Provider.LOCAL;
    @ManyToMany(fetch =FetchType.EAGER)
    @JoinTable(name = "user_roles",joinColumns = @JoinColumn(name = "user_id"),inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();
    @PrePersist
    protected void onCrete(){
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }
    @PreUpdate
    protected void onUpdate(){
        updatedAt = Instant.now();
    }


//    under all method are for spring security to work with our user entity
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return roles
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();
    }

    @Override
    public String getUsername() {
        return this.email;
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
        return this.enable;
    }
}
