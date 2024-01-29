# Spring security 예제
* 강의 : 최주호님의 스프링부트 시큐리티 & JWT 강의 ( https://inf.run/R1AW )
* 사용 버전
  * spring boot ***(3.1.1)***
  * spring boot oauth2 client(3.1.1)
  * spring security ***(6.1.x)***
  * spring data JPA
  * mySql

<br/>

## (Spring boot 3.X + Spring Security 6.X) 변경사항

### 1. SecurityFilterChain 설정 방법 변경
* 람다를 사용해서 설정합니다.
* 출처: https://docs.spring.io/spring-security/reference/migration-7/configuration.html
* 출처 : https://docs.spring.io/spring-security/reference/reactive/integrations/cors.html

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/blog/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(formLogin -> formLogin
                .loginPage("/login")
                .permitAll()
            )
            .rememberMe(Customizer.withDefaults());

        return http.build();
    }
}
```

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
	CorsConfiguration configuration = new CorsConfiguration();
	configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
	configuration.setAllowedMethods(Arrays.asList("GET","POST"));
	UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	source.registerCorsConfiguration("/**", configuration);
	return source;
}

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .cors(configurer ->
                configurer.configurationSource(corsConfigurationSource())
        )
        ...

    return http.build();
}
```

<br/>

### 2. AuthenticationManager 등록 방법
* Bean을 등록해서 사용합니다
* 출처 : https://stackoverflow.com/questions/74877743/spring-security-6-0-dao-authentication

```java
@Bean
public AuthenticationManager authenticationManager(){
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailService);
    authProvider.setPasswordEncoder(getPassWordEncoder());
    return new ProviderManager(authProvider);
}
```

<br/>

## Further Study 

### 1. 여러개의 SecurityFilterChain 등록하는 방법
* securityMatchers 함수를 사용합니다
* 예제 : https://github.com/devwuu/VRS_VETReservationSystem
* 출처 : https://docs.spring.io/spring-security/reference/5.8/migration/servlet/config.html#use-new-security-matchers
* 출처 : https://www.danvega.dev/blog/2023/04/20/multiple-spring-security-configs/

```java

    @Bean
    public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatchers((matchers) -> matchers
                        .requestMatchers("client/**", "v1/client/**")
                )
		...

        return http.build();
    }

    @Bean
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatchers((matchers) -> matchers
                        .requestMatchers("admin/**", "v1/admin/**")
                )
		...

        return http.build();
    }

```

<br/>

### 2. login url을 custom 하는 법
* 로그인을 담당하는 filter에 url을 맵핑시켜준다
* 예제 : https://github.com/devwuu/VRS_VETReservationSystem
* 출처 : https://stackoverflow.com/questions/49583373/how-to-change-login-url-in-spring-security

```java

   @Bean
    public AdminAuthenticationFilter adminAuthenticationFilter(){
	...
        adminAuthenticationFilter.setFilterProcessesUrl("/admin/token");
        adminAuthenticationFilter.setPostOnly(true);
        return adminAuthenticationFilter;
    }

```

<br/>

### 3. AuthorizationFilter에서 사용하지 않는 authenticationManager를 제외하고 Filter를 구현하는 방법
* OncePerRequestFilter 를 상속받는다
* 이 경우엔 Filter를 등록할 때 Filter의 순서를 정해줘야한다
* 주의 : OncePerRequestFilter의 경우 Bean으로 등록하면 securityMatchers에 관계 없이 모든 filterChain에 등록되기 때문에   
  (1) filterChain이 복수개일 경우 Bean으로 등록하지 않거나(new 연산자로 filterChain에 등록)   
  (2) shouldNotFilter() 메서드를 overriding하여 제외시킬 url을 등록해준다
* 예제 : https://github.com/devwuu/VRS_VETReservationSystem
* 출처 : https://www.toptal.com/spring/spring-security-tutorial

```java

package com.web.vt.security;

import com.auth0.jwt.JWT;
import com.web.vt.utils.StringUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AdminAuthorizationFilter extends OncePerRequestFilter {

    private final AdminDetailService adminDetailService;

    public AdminAuthorizationFilter(AdminDetailService adminDetailService) {
        this.adminDetailService = adminDetailService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        if(StringUtil.isEmpty(authorization) || !StringUtil.startsWith(authorization, JwtProperties.PRE_FIX)){
            filterChain.doFilter(request, response);
            return;
        }

        String id = JWT.require(JwtProperties.SIGN)
                .build()
                .verify(StringUtil.remove(authorization, JwtProperties.PRE_FIX))
                .getClaim("id")
                .asString();

        AdminPrincipal principal = (AdminPrincipal) adminDetailService.loadUserByUsername(id);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String url = request.getRequestURI();
        return Stream.of("/client/**", "/v1/client/**").anyMatch(x -> new AntPathMatcher().match(x, url));
    }
}
```

```java

    @Bean
    public AdminAuthorizationFilter adminAuthorizationFilter(){
        return new AdminAuthorizationFilter(adminDetailService());
    }

    @Bean
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
		...
                .addFilter(adminAuthenticationFilter())
                .addFilterBefore(adminAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

```

또는

```java

package com.web.vt.security;

import com.auth0.jwt.JWT;
import com.web.vt.utils.StringUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AdminAuthorizationFilter extends OncePerRequestFilter {

    private final AdminDetailService adminDetailService;

    public AdminAuthorizationFilter(AdminDetailService adminDetailService) {
        this.adminDetailService = adminDetailService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        if(StringUtil.isEmpty(authorization) || !StringUtil.startsWith(authorization, JwtProperties.PRE_FIX)){
            filterChain.doFilter(request, response);
            return;
        }

        String id = JWT.require(JwtProperties.SIGN)
                .build()
                .verify(StringUtil.remove(authorization, JwtProperties.PRE_FIX))
                .getClaim("id")
                .asString();

        AdminPrincipal principal = (AdminPrincipal) adminDetailService.loadUserByUsername(id);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(request, response);
    }
}
```

```java
    @Bean
    public SecurityFilterChain adminFilterChain(HttpSecurity http,
                                                @Qualifier("adminAuthenticationFilter") UserAuthenticationFilter authenticationFilter,
                                                        AdminDetailService detailService,
                                                        JwtUtil jwtUtil) throws Exception {
            http
            ....
            .addFilter(authenticationFilter)
            .addFilterBefore(new UserAuthorizationFilter(detailService, jwtUtil), AuthorizationFilter.class)
            .addFilterAt(new FilterExceptionHandler(), ExceptionTranslationFilter.class);
    
            return http.build();
        }

```

<br/>

### 4. JWT Property(JWT 설정) 환경별로 분리하기
* application-{환경}.yml로 각 환경별로 설정을 분리한다
* yml의 속성값을 읽어오는 class를 작성한다
* Application을 실행할 때 Active Profile을 설정해준다
* 추가로 JwtProvider를 구현하여 JWT 토큰 발급, 인증 로직 등을 공통화하면 AuthenticationFilter나 AuthorizationFilter에서 Property에 직접 의존하는 걸 막고 유지보수성을 높일 수 있다
* 예제 : https://github.com/devwuu/VRS_VETReservationSystem
* 출처 : https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.external-config.typesafe-configuration-properties.relaxed-binding
* 출처 : https://velog.io/@max9106/Spring-Boot-외부설정-4xk69h8o50

```yml
...
spring:
  config:
    activate:
      on-profile: dev
app:
  security:
    jwt:
      secret: dev
      limit: 10
      issuer: localhost:8090
...
```

```yml
...
spring:
  config:
    activate:
      on-profile: local
...
app:
  security:
    jwt:
      secret: local
      limit: 1440
      issuer: localhost:8080

...
```

```java

@ConfigurationProperties(prefix = "app.security.jwt")
@Getter @Setter
public class JwtProperties {

    private String secret;
    private int limit;
    private String issuer;
    private String prefix = "Bearer ";

    public Instant getExpiredTime(){
        return LocalDateTime.now().plusMinutes(limit).toInstant(ZoneOffset.UTC);
    }

    public Algorithm getSign(){
        return Algorithm.HMAC256(secret);
    }

}

```

```java
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class AppConfiguration {

...

}

```

<br/>

### 5. 테스트
* MockMvc를 사용하는 경우, MockMvcBuilders에 WebApplicationContext, springSecurity를 셋팅하고 build한다
* UserDetail을 사용해야 하는 경우, @WithUserDetails 어노테이션을 사용한다.
	* userDetailsServiceBeanName 은 custom한 userDetailService 이고 value는 username이다
	* 지정한 userDetailService에서 지정한 Username으로 user를 조회한다
* 3번처럼 profile이 나눠져있는 경우 @ActiveProfiles 어노테이션을 사용한다
* 예제 : https://github.com/devwuu/VRS_VETReservationSystem
* 출처 : https://docs.spring.io/spring-security/reference/servlet/test/mockmvc/setup.html
* 출처 : https://tecoble.techcourse.co.kr/post/2020-09-30-spring-security-test/

```java
@SpringBootTest
@AutoConfigureMockMvc
@Disabled
@Transactional
@ActiveProfiles("local")
public class ControllerTestSupporter {

    protected MockMvc mvc;
    ...

    @BeforeEach
    void setUp(WebApplicationContext context, RestDocumentationContextProvider provider) {

        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                ...
                .build();
    }

}

```

```java
@WithUserDetails(userDetailsServiceBeanName = "employeeDetailService", value = "test")
class ReservationClientControllerTest extends ControllerTestSupporter {
	...
}
```

<br/>

## local에서 CORS 설정 테스트하기

### 테스트용 스크립트
* terminal을 사용합니다
* 출처: https://beanbroker.github.io/2019/12/01/etc/cors_curl

```shell
curl -I -X OPTIONS \
  -H "Origin: http://localhost:8090" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/home
```

<br/>

### 결과 예시

```shell
curl -I -X OPTIONS \
  -H "Origin: http://localhost:8999" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/home
HTTP/1.1 403
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Transfer-Encoding: chunked
Date: Tue, 25 Jul 2023 07:30:00 GMT
```
```shell
curl -I -X OPTIONS \
  -H "Origin: http://localhost:8090" \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/home
HTTP/1.1 200
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Access-Control-Allow-Origin: http://localhost:8090
Access-Control-Allow-Methods: GET
Access-Control-Allow-Credentials: true
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Length: 0
Date: Tue, 25 Jul 2023 07:30:04 GMT
```
