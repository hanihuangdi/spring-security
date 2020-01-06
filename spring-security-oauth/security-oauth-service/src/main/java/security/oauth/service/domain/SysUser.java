package security.oauth.service.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class SysUser implements UserDetails {
    private Integer id;
    private String username;
    private  String password;
    private  Integer status;
    private List<SysRole> roles;
   // private List<SysRole> authorities;

    public List<SysRole> getRoles() {
        return roles;
    }

    public void setRoles(List<SysRole> roles) {
        this.roles = roles;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }
}
