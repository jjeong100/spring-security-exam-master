package com.example.vue.board.exam.config.auth;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.ObjectUtils;

import com.example.vue.board.exam.entity.User;

import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;


//  시큐리티가 /loginProc요청이 오면 낚아채서 로그인을 진행 시킨다
// 로그인 진행이 완료가 되면 시큐리티 session(우리가 백에서 만드는 세션이랑 똑같은데 시큐리티가 관리하는 세션임)을 만들어줍니다.
// (Security ContextHolder라는 키값으로 정보를 가지고 있습니다.)
// 이 정보는 Authentication 타입의 객체이고 안에 User 정보가 담겨있다.
// User 정보는 UserDetails 타입의 객체이다

// 즉, 세션 안에 있는 security session 영역이 있는데 이 안에는 Authentication 타입의 객체만 저장된다
// 이 Authentication 객체 안에 User정보가 저장되는데 User정보는 UserDetails 타입의 객체이다.

@Slf4j
@ToString
@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {
                                // 이렇게 userDetails 타입을 구현 시키게 돠면 다형성에 의거해서 Authentication 객체에
                                // PrincipalDetails 타입을 넣을 수 있게 된다 (구현체니까~ )

    private User user;
    private Map<String, Object> attributes;

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // UserDetails 구현
    // 해당 유저의 권한을 return 하는 메서드
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of((GrantedAuthority) () -> user.getRole());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 이 계정 안 만료 됐니?
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 이 계정 안 잠겼니?
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 이 계정 비밀번호 안 만료됐니?
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 이 계정 사용 가능하니?
    @Override
    public boolean isEnabled() {
        // 예를 들어 1년 이상 로그인 안 한 계정을 비활성화 시켜서 로그인 못하게 막을 수 있는.. 그런 로직을 구현하는 자리이다.
        return true;
    }

    // 각각의 메서드에 user 정보를 가지고 필요한 로직을 구현시키는 방향으로 작성하면 된다.
    // UserDetails 구현


    // OAuth2User 구현
    @Override
    public String getName() {
        if(ObjectUtils.isEmpty(attributes) || ObjectUtils.isEmpty(attributes.get("sub"))){
            return null;
        }
        return attributes.get("sub").toString();
    }


    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }
    // OAuth2User 구현


}
