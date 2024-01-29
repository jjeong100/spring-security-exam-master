package com.example.vue.board.exam.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.example.vue.board.exam.config.oauth.PrincipalOauth2UserService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록 됩니다
@EnableMethodSecurity(securedEnabled = true) // secured 어노테이션 활성화,
                                            // prePostEnabled는 true가 default값이다 PreAuthorize, PostAuthorize 어노테이션 활성
                                            // 권한 설정을 전역으로 하고 싶을 때는 requestMatchers 로 걸어주고
                                            // 일부만 설정하고 싶을 때는 이 어노테이션들을 활성화시켜서 사용하면 된다.
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService oauth2UserService;

    @Bean // 시큐리티 기본 설정, 인증 및 인가 설정
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(configurer -> configurer.disable())
            .authorizeHttpRequests(registry ->
                    registry.requestMatchers("/user/**").authenticated()
                            .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN") // prefix(ROLE_)이 자동으로 붙기 때문에 여기선 prefix를 제외한 문자열만 써주면 된다
                                                                                                        // 단, DB에는 ROLE_을 붙여서 적어줘야 제대로 맵핑이 된다.
                            .requestMatchers("/admin/**").hasRole("ADMIN")
                            .anyRequest().permitAll()
            )
            .formLogin(configurer ->
                        configurer.loginPage("/login")
                                .loginProcessingUrl("/loginProc")
                                .defaultSuccessUrl("/")
                                // .usernameParameter() service에 파라미터로 넘어가는 username의 파라미터 이름을 바꿔줄 수 있습니다.
            )
                // 구글 로그인 프로세스
                // 1. 로그인
                // 2. 정상적으로 로그인 된 경우 코드를 줌 (인증)
                // 3. 코드를 통해서 액세스 토큰을 받음
                // 4. 액세스 코드를 사용해서 구글 사용자의 사용자 정보에 접근할 수 있음(접근 권한이 생김)
                // 5 - 1. 사용자 프로필 정보를 가져와서 정보를 토대로 회원가입을 자동으로 진행 시키거나
                // 5 - 2. 추가적인 정보를 더 받고 회원가입을 시켜주기도 함
                // oauth client 라이브러리를 사용하면 코드를 받아서 처리할 필요 없이 바로 액세스 토큰과 사용자 프로필 정보를 받아올 수 있다.
            .oauth2Login(configurer -> configurer
                        .loginPage("/login") // google login page와 로그인 페이지를 맵핑 시켜줍니다.
                    .userInfoEndpoint(config -> config.userService(oauth2UserService))
            );

                // requestMatchers : request 경로가 이쪽인 사람들은...
                // authenticated : 인증(로그인)된 사람만 들어올 수 있다.
                // hasAnyRole : 인증 뿐만 아니라 인가(권한)된 사람만 들어올 수 있다.
                // hasAnyRole : 인증 뿐만 아니라 인가(권한)된 사람만 들어올 수 있다.
                // anyRequest : 나머지 요청들은 인증/인가 설정이 없음
                // loginPage: 로그인 페이지 url을 설정해서 권한이 없을 때 해당 페이지로 떨어지게 만들 수 있다
                // loginProcessingUrl : 로그인 처리 로직을 수행하는 request URL을 security가 낚아채서 수행하게 한다
                                        // 따라서 내가 controller를 만들지 않아도 됨
                // defaultSuccessUrl : 로그인한 사용자를 redirect 시킬 기본 url
                                    // 만약 이 사용자가 권한이 필요한 페이지에서 튕겨져나와서 로그인 페이지로 넘어와 로그인에 성공한 거라면
                                    // 사용자가 본래 접속하려고 했던 권한 페이지로 자동 리다이렉트 시켜주고
                                    // 만약 그런 페이지가 아니라 일반 공개된 페이지에서 넘어온 거라면 여기에 설정된 default url로 넘겨준다.


        return http.build();
    }


}
