## 기술 개념 정리

1. Spring
- Spring (Spring Framework)
  - 자바 플랫폼을 위한 오픈소스 애플리케이션 프레임워크
  - 동적인 웹 사이트를 개발하기 위한 여러 가지 서비스를 제공
  - Spring 특징
    - 경량 Container
    - DI(Dependency Injection)
      - 의존성에 의한 문제점
        - Unit Test가 어려워진다 -> 내부에서 직접 생성하는 객체에 대해 mocking을 할 방법이 없음
        - Code 변경이 어려워진다 -> 객체간의 강한 결합력이 생긴다(모듈화의 목적에 해가 되는 행위)
      - 의존성 주입(Spring 사용전)
        - 생성자를 통해 전달 받음
        - setter를 통해 전달 방법
      - DI(Spring 사용)
        - DI 방식을 이용하여 모듈간 결합도를 낮춰준다.
        - IOC Container가 개발자 대신 xml 파일에 정의된 대로 Bean 객체를 생성하고 의존성을 대신 주입하는 것
        - IOC(제어의 역전) : 사용자가 직접 객체를 생성하고 관리하던 것을 spring IOC Container가 대신 해준 다는 말
    - 제어 역행(IoC: Inversion of Control)
      - 애플리케이션의 느슨한 결합을 도모
      - 컨트롤의 제어권이 사용자가 아니라 프레임워크에 있어 필요에 따라 스프링에서 사용자의 코드를 호출
      - IoC Conatiner : 사용자가 작성한 메타데이터(xml or @(어노테이션))에 따라 Bean클래스를 생성 및 관리하는 Spring 핵심 컴포넌트
        - Bean 정의를 읽어들이고, Bean을 구성하고 제공
      - IoC Container의 설정 방법
        - XML 파일 기술 : Code와 의존성을 주입하는 부분을 분리할 수 있다.
          - 유지보수성을 높일 수 있다.
          - 각 객체들의 의존관계를 한눈에 볼 수 있다.
          - 규모가 커짐에 따라 XML에 기술할 내용이 많아지면 생산성이 저하되고 유지보수가 어려워진다.
        - @(어노테이션)사용
          - 더 직관적인 코드 작성이 가능해진다
          - 메타데이터와 소스코드를 같이 기술 -> 개발 생산성이 증대
        - BeanFactory : Bean의 생성과 설정, 관리를 맡고 있음
        - ApplicationContext : BeanFactory를 상속받고 있기 때문에 BeanFactory와 같은 일 수행
        - Bean : 컨테이너 안에 들어 있는 객체들
          - 의존성 주입을 하기위해 Bean이 되어야하며 의존성 주입은 bean끼리만 가능
    - 관전지향 프로그래밍(AOP : Aspect-Oriented Programming)
      - 트랜잭션이나 로깅, 보안과 같이 여러 모듈에서 공통적으로 사용하는 기능의 경우 해당 기능을 분리하여 관리 가능
      - 핵심 기능외 부수 기능들을 분리 구현함으로 모듈성을 증가시키는 방법 (공통된 기능을 재사용하는 기법)
      - 어플리케이션 전체에 흩어진 공통 기능이 하나의 장소에 관리
      - 다른 서비스 모듈이 본인 목적에 충실하고 그 외 사항을 신경쓰지 않음
    - Container : 애플리케이션 객체의 생명 주기와 설정을 포함하고 관리
      - iBatis, myBatis나 Hibernate 등 완성도 높은 데이터베이스처리 라이브러리와 연결 할 수 있는 인터페이스 제공
    - 트랜잭션 관리 프레임워크
      - 추상화된 트랜잭션 관리를 지원하며 설정 파일(xml, java, property 등)을 이용한 선언적 방식 및 프로그래밍을 통한 방식 모두 지원
    - MVC 패턴
      - DispatcherServlet이 Controller 역할을 담당하며 각종 요청을 적절한 서비스에 분산시켜주며 각 서비스들이 처리를 하여 결과를 생성하고 다양한 형식의 View 서비스들로 화면에 표시
    - 배치 프레임워크
      - 특정 시간대 실행 or 대용량의 처리하는데 쓰이는 일괄처리를 지원하는 프레임워크 제공
    - POJO(plain old java object) 방식 프레임워크
      - Java의 객체지향적 특징을 살려 비즈니스 로직에 출시해 개발이 가능하도록 하는 것
      - 특정 규약과 환경에 종속되지 않음.
      - 단일 책임 원칙을 지키는 클래스
      - 코드의 간결하며 자동화 테스트에 유리하다
  - 스프링 모듈
    - Spring Core : Spring 프레임워크의 근간이 되는 요소. IoC 기능을 지원하는 영역 담당
      - BeanFactory를 기반으로 Bean 클래스들을 제어할 수 있는 기능 지원
    - Spring Context 
      - Spring Core 바로위에 있으며 Spring Core에서 지원하는 기능외 추가적 기능과 더 쉬운 개발이 가능하도록 지원
      - JNDI, EJB등을 위한 Adaptor들 포함
    - Spring DAO
      - JDBC 기반하의 DAO개발을 좀 더 쉽고, 일관된 방법으로 개발하는 것이 가능하도록 지원
      - Spring DAO를 이용할 경우 지금까지 개발하던 DAO보다 적은 코드, 쉬운방법으로 dao개발하는것 가능
    - Spring ORM
      - Object Relation Mapping 프레임워크인 Hibernate, Ibatis, JDO와 결합을 지원하기위한 기능
    - Spring AOP
      - Aspepct Oriented Programming을 지원하는 기능(AOP Alliance기반하에 개발)
    - Spring Web
      - Web Application 개발에 필요한 Web Application Context와 Mutipart Request등의 기능 지원
      - Struts, Webwork와 같은 프레임워크의 통합을 지원하는 부분 담당
    - Spring Web  MVC
      - Spring 프레임워크에서 독립적으로 Web UI Layer에서 Modle-View-Controller를 지원하기 위한 기능
   
  - EJB(Enterprise JavaBean)
    - Java EE는간편하고 견고하고 확장가능하며 안전한 서버측 자바 애플리케이션을 위한 산업 표준
    - Java EE에는 웹 애플리케이션 개발을 위한 Servlet, JSP, EJB 등 다양한 기능을 포함
  - Java EE의 기능
    - 비동기 메시지 처리를 위한 JMS(Java Message Service)
    - 데이터베이스 처리용 API JDBC(Java Database Connectivity)
    - 트랜잭션 처리를 위한 JTA (Java Trasaction Api)
    - 분산 트랜잭션 지원 및 디렉토리 서비스를 위한 JNDI(Java Naming and Directory Interface)
  - EJB 기능
    - 분산 애플리케이션ㅇ르 지원하는 컴포넌트 기반의 객체 --> 재사용성 있음.
  - EJB 장단점
    - 대량의 트랜잭션을 안정적으로 처리 가능
    - 분산 트랜잭션을 지원
    - 인증과 접근제어에 용이
    - 복잡한 프로그래밍 모델
    - 특정 환경 및 기술에 종속적인 코드
    - 컨테이너 안에서만 동작할 수 있는 객체구조
    - 자동화된 테스트가 매우 어렵거나 불가능
    - 객체지향적이지 않고 형편없는 개발생산성
      
2. Spring Boot
  - Spring Framework를 사용하기 위한 설정의 많은 부분을 자동화하여 사용자가 정말 편리하게 스프링을 활용할 수 있도록 도움을 줌.
  - 자동설정 : 필요한 설정 자동으로 구성 -> 버전 문제 발생률 줄어듬
  - XML 없는 환경 구축 -> 자바 코드로 설정 가능
  - Tomcat 내장 -> 서버를 빠르게 구동 가능 
  - Spring Boot 장단점
    - 애플리케이션을 신속하게 설정, 스프링 구동 애플리케이션을 빌드하기위한 기본 구성 제공 유틸리티
    - 상용화에 필요한 통계, 상태 체크, 외부 설정 등을 제공, 기본설정된 starter 컴포넌트 제공
    - WAS 설치 없이 embeded container에서 자신의 애플리케이션 실행 가능
    - Tomcat, Jetty, Undertow 가 기본 내장되어 있다. -> 웹 프로젝트 띄우는 시간 단축
    - .jar 파일 형태로 간단히 배포가능하다.
    - 의존라이브러리의 버전을 일일이 지정않아도 되며 스프링 부트가 권장 버전을 관리
    - 내장 톰캣 관리가 어려움
    - 같은 서버 포트번호로 다르게 배포시 boot 버전을 맞춰야한다.

3. Spring Security
- 스프링 기반의 애플리케이션 보안(인증과 권한, 인가 등)을 담당하는 스프링 하위 프레임워크 
  - 서블릿 필터와 이들로 구성된 필테체인으로의 위임 모델 사용 
  - Spring Security는 전적으로 Servlet Filter를 기반으로 한다
  - Filter는 요청과 응답을 가로채고 해당요청/응답 전후에서 필요한 처리를 할 수 있다
- 사용자 정의가 가능한 인증 및 접근 제어/권한 프레임워크
  - 인증 : id/pw, 공인인증서 등
  - 권한 : admin, user, guest 등
- 간략한 과정
  
  ![ex_screenshot](/res/security2.JPG)
  
  1. Authorization(권한) : 권한이 없는 User가 접근 시 자동으로 Login Page 띄어줌
  2. Authentication(인증) : 사용자가 입력한 id/pw가 일치하는지 Authentication Providers를 통해 확인
  3. id/pw가 일치하지 않으면 반복
  4. 인증과 권한이 통과도면 Secured Area에 접근 허용
- 1) Security Architecture
  - Form 기반 로그인에 대한 플로우
  
  ![ex_screenshot](/res/security.png)
  1. 사용자가 Form을 통해 로그인 정보 입력 후 인증 요청
  2. AuthenticationFilter가 HttpServletRequest에서 사용자가 보낸 id/pw를 인터셉트
    - 유효성 검사
    - HttpServletRequest에서 꺼내온 사용자 id/pw를 AuthenticationManaver 인터페이스(구현체-ProviderManager)에 인증용 객체(UsernamePawsswordAuthentication Token)로 만들어 위임
  3. AuthenticationFilter에게 인증용 객체를 전달 받음.
  4. 실제 인증할 AuthenticationProvider에게 Authenticatin객체를 다시 전달 
  5. DB에서 사용자 인증 정보를 가져올 UserDetailService 객체에게 사용자 아이디 넘겨주고 DB에서 인증에 사용할 사용자정보(id, 암호화된 pw, 권한 등)를 UserDetials(인증용 객체와 도메인 객체를 분리하지 않기 위해 실제 사용되는 도메인 객체에서 UserDetails를 상속하기도 함)라는 객체로 전달 받는다. 
  6. AuthenticationProvider는 UserDetails 객체를 전달 받은 이후 실제 사용자 입력정보와 UserDetails 객체를 가지고 인증을 시도
  7. 인증이 완료되면 사용자 정보를 가진 Authentication 객체를 SecurityContextHolder에 담은 이후 AuthenticationSuccessHandle를 실행(실패시 AuthenticationFailureHandler를 실행)

- 2)security filter들
  - SecurityContextPersistenceFilter : SecurityContextRepository에서 Security를 가져오거나 저장
  - LogoutFilter : 설정된 로그아웃 URL로 오는 요청을 감시하며, 해당 유저를 로그아웃 처리
  - (UsernamePassword)AuthenticationFilter : 설정된 로그인 URL로 오는 요청을 감시하며 유저 인증 처리
    - AuthenticationManager를 통한 인증 실행
    - 인증 성공 시, Authentication 객체를 SecurityContext에 저장 후 AuthenticationSuccessHandler 실행
    - 인증 실패 시, AuthenticationFaiureHandler 실행
  - DefualtLoginPageGeneraterFilter : 인증을 위한 로그인폼 URL을 감시
  - BasicAuthenticationFilter : HTTP 기본 인증 헤더를 감시하여 처리
  - RequestCacheAwareFilter : 로그인 성공 후, 원래 요청 정보를 재구성하기 위해 사용
  - SecurityContextHolderAwareRequestFilter : HttpServletRequestWraaper를 상속한 SecurityContextHolderAwareRequestWrapper 클래스로 HttpServletRequest정보를 감싼다. SecurityContextHolderAwareRequestWrapper 클래스는 필터 체인상의 다임 필터들에게 부가정보를 제공
  - AnonymousAuthenticatonFilter : 이 필터가 호출되는 시점까지 사용자 정보가 인증되지 않는다면 인증토큰에는 익명 사용자로 나타남
  - SesseionManagementFilter : 인증된 사용자와 관련된 모든 세션을 추적
  - ExceptionTranslationFilter : 보호된 요청을 처리하는 중에 발생할 수 있는 예외를 위임하거나 전달하는 역할 수행
  - FilterSecurityInterceptor : AcessDecisionManager로 권한부여 처리를 위윔하므로 접근 제어 결정을 쉽게한다. 
- 3) Authentication
  - 접근 주체는 Authentication 객체 생성, SecurityContext에 보관되고 사용된다
  <pre>
  <code>
  public interface Authentication extends Principal, Serializable { 
      Collection<? extends GrantedAuthority> getAuthorities(); 
      // Authentication 저장소에 의해 인증된 사용자의 권한 목록 
      Object getCredentials(); // 주로 비밀번호 
      Object getDetails(); // 사용자 상세정보 
      Object getPrincipal(); // 주로 ID 
      boolean isAuthenticated(); //인증 여부 
      void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException; 
  }
  
  </code>
  </pre>
  
- 4) AuthenticationManager

  ![ex_screenshot](/res/security3.png)
- 유저의 요청을 AuthenticationFilter에서 Authentication객체로 변환하여 AuthenticationManager(ProvidrMnager)에게 넘겨주고, AuthenticationProvider가 실제 인증을 한 후 인증이 완료되면 Authentication 객체를 반환
  - AbstractAuthenticationProcessingFilter : 웹 기반 인증요청에서 사용되는 컴포넌트
    - POST 폼 데이터를 포함하는 요청을 처리
    - 사용자 비밀번호를 다른 필터로 전달하기 위해 Authentication 객체를 생성하고 일부 프로퍼티를 설정
  - AuthenticationManager : 인증요청을 받고 Authentication을 채워준다
  - AuthenticationProvider : 실제 인증이 일어나고 인증 설공시 Authentication 객체의 authenticated=true 설정
- Spring Securitiy는 ProviderManager라는 AuthenticationManager 인터페이스의 유일한 구현체를 제공
- ProviderManager는 하나 or 여러 개의 AuthenticationProvider 구현체를 사용할 수 있다
- AuthenticationProvider는 많이 사용되고 ProviderManager(AuthenticationManager의 구현체)와도 잘 통합되기때문에 기본적으로 어떻게 동작하는지 이해하는 것이 중요!

- 5) 비밀번호 인증과정
  ![ex_screenshot](/res/security4.png)
  - DaoAuthenticationProvider는 UserDetailService 타입 오브젝트로 위임
  - UserDetailService는 UserDetails 구현체를 리턴하는 역할 
    - Authentication : 사용자 id, pw와 인증 요청 컨텍스트에 대한 정보를 가짐, 인증 이후의 사용자 상세정보와 같은 UserDetails 타입 오브젝트를 포함 할 수도 있음
    - UserDetails : 이름, 이메일, 전화번호와 같은 사용자 프로파일 정보를 저장하기 위한 용도로 사용
- 6) 인증예외
  - 인증과 관련되 모든 예외는 AuthenticationException을 상속 
    - authentication : 인증 요청관련 Authentication 객체를 저장
    - extrainformation : 인증 예외 부가 정보 저장

- 접근 권한 부여
  - FilterSecurityInterceptor : 요청의 수락 여부 결정 
    - Authentication의 getAuthorities 메소드 참조하여 해당 요청의 승인 여부를 결정 
    - AccessDecisionManager 컴포넌트가 인증 확인 처리

- JavaConfig
자료 출처 : https://coding-start.tistory.com/153
<pre>
<code>
@EnableWebSecurity // 스프링 시큐리티를 사용하겠다는 선언
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{
    
//    private UserDetailsService userDetailsService;
//    private PasswordEncoder passwordEncoder;
    private AuthenticationProvider authenticationProvider;
    
    public SpringSecurityConfig(/*UserDetailsService userDetailsService, 
                                PasswordEncoder passwordEncoder,*/
                                AuthenticationProvider authenticationProvider) {
//        this.userDetailsService = userDetailsService;
//        this.passwordEncoder = passwordEncoder;
        this.authenticationProvider = authenticationProvider;
    }
    
    /*
     * 스프링 시큐리티가 사용자를 인증하는 방법이 담긴 객체.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*
         * 인증을 담당할 프로바이더 AuthenticationProvider 구현체를 설정하는 메소드 
         */
        auth.authenticationProvider(authenticationProvider); // Custom한 Provider
//        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }
    
    /*
     * 스프링 시큐리티 룰을 무시하게 하는 Url 규칙.
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
            .antMatchers("/resources/**")
            .antMatchers("/css/**")
            .antMatchers("/vendor/**")
            .antMatchers("/js/**")
            .antMatchers("/favicon*/**")
            .antMatchers("/img/**")
        ;
    }
    
    /*
     * 스프링 시큐리티 룰.
     * 권한 설정, Handler 등록, Custom Filter 등록, 예외 핸들러 등록 등 수행
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/login*/**").permitAll()
            .antMatchers("/logout/**").permitAll()
            .antMatchers("/chatbot/**").permitAll()
            .anyRequest().authenticated()
        .and().logout()
              .logoutUrl("/logout")
              .logoutSuccessHandler(logoutSuccessHandler())
        .and().csrf()
              .disable()
        .addFilter(jwtAuthenticationFilter())
        .addFilter(jwtAuthorizationFilter())
        .exceptionHandling()
              .accessDeniedHandler(accessDeniedHandler())
              .authenticationEntryPoint(authenticationEntryPoint())
//        .and().sessionManagement()
//              .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        ;
    }
    
    /*
     * SuccessHandler bean register
     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        CustomAuthenticationSuccessHandler successHandler = new CustomAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/index");
        return successHandler;
    }
    
    /*
     * FailureHandler bean register
     */
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        CustomAuthenticationFailureHandler failureHandler = new CustomAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/loginPage?error=error");
        return failureHandler;
    }
    
    /*
     * LogoutSuccessHandler bean register
     */
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        CustomLogoutSuccessHandler logoutSuccessHandler = new CustomLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl("/loginPage?logout=logout");
        return logoutSuccessHandler;
    }
    
    /*
     * AccessDeniedHandler bean register
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/error/403");
        return accessDeniedHandler;
    }
    
    /*
     * AuthenticationEntryPoint bean register
     */
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint("/loginPage?error=e");
    }
    
    /*
     * Form Login시 걸리는 Filter bean register
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager());
        jwtAuthenticationFilter.setFilterProcessesUrl("/login");
        jwtAuthenticationFilter.setUsernameParameter("username");
        jwtAuthenticationFilter.setPasswordParameter("password");
        
        jwtAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        jwtAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        
        jwtAuthenticationFilter.afterPropertiesSet();
        
        return jwtAuthenticationFilter;
    }
    
    /*
     * Filter bean register
     */
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() throws Exception {
        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(authenticationManager());
        return jwtAuthorizationFilter;
    }
}
</code>
</pre>

4. MVC 패턴
- 프로젝트를 구성할 때 Model, View, Controller 세가지 역할로 구분한 패턴
  ![ex_screenshot](/res/mvc.png)
- Model : 애플리케이션 정보, 데이터를 나타냄
  - 비즈니스 로직을 처리하기 위한 역할 수행
  - 데이터베이스, 처음 정의하는 상수, 초기화값 변수 등.. 이러한 데이타, 정보 가공을 책임지는 컴포넌트
  - 사용자가 편집하길 원하는 모든 데이터를 가지고 있어야함.
  - 뷰나 컨트롤러에 대해 어떤 정보도 알지 말아야함
  - 변경이 일어나면, 변경 통지에 대한 처리방법을 구현해야한다.
  - 모델은 재사용 가능해야하며 다른 인터페이스에서도 변하지 않아야함
- View : 사용자 인터페이스 요소를 나타냄
  - 화면에 무엇인가를 보여주기 위한 역할 수행 
  - 데이터 및 객체 입력, 출력 담당
  - 모델이 가지고 있는 정보를 따로 저장해서는 안됨
  - 모델이나 컨트롤러와 같이 다른 구성요소들은 몰라야 함.
  - 변경이 일어나면 변경 통지에 대한 처리방법을 구현해야 한다.
- Controller : 데이터와 사용자인터페이스들을 잇는 다리역할
  - 모델이 어떻게 처리할 지 알려주는 역할, 화면의 로직 처리 부분
  - 사용자가 데이터를 클릭하고, 수정하는 것에 대한 "이벤트"들을 처리하는 부분
  - 모델이나 뷰에 대해 알고 있어야한다
    - 모델이나 뷰는 서로 존재를 모르고, 변경을 외부로 알리고, 수신하는 방법만 가지며 이를 컨트롤러가 중재하기 위해 모델과 뷰에 대해 알고 있어야함
  - 모델이나 뷰의 변경을 모니터링 해야 한다
- 동작 순서
  - 사용자의 Action들은 Controller에 들어오게됨
  - Controller는 사용자 Action을 확인하고 Model을 업데이트
  - Controller는 Model을 나타내줄 Viewe 선택
  - View는 Model을 이용하여 화면을 나타냄
- 처리 과정

  ![ex_screenshot](/res/mvc2.JPG)
  - 클라이언트 요청이 DispatcherServlet에 전달
  - DispatcherServlet은 HandlerMapping을 사용, 클라이언트의 요청을 처리할 컨트롤러 객체를 찾음
  - DispatcherServlet은 컨트롤 객체의 handleRequest() 메소드를 호출하여, 클라이언트의 요청을 처리
  - Controller.handleRequest() 메소드는 처리 결과 정보를 담은 ModelAndView 객체를 리턴
  - DispatcherServlet은 ViewResolver로 부터 처리결과를 보여줄 View를 구한다
  - View는 클라이언트에 전송할 응답을 생성

- MVC 한계
  - View와 Model 사이의 의존성이 높아 복잡해지며 유지보수가 어려울 수 있다.
  - View는 Controllere에 연결되어 화면을 구성하는 단위요소로 다수의 View를 가질 수 있다
  - Model은 Controller를 통해 View와 연결되어지지만, Contoller를 통해 하나의 View에 연결될 수 있는 Model도 여러개가 될 수 있다
  - 화면에 복잡한 화면, 데이터의 구성이 필요하다면 Controller에 다수의 Model과 View가 복잡하게 연결되는 상황이 생길 수 있다 (Massive ViewController)
    - MVC가 복잡해지고 비대해져, 새로운 기능을 추가할 때마다 크고 작은 문제점을 가지게 된다.
- MVC 패턴 장점
  - 서로 분리되어 각자 역할에 집중할 수 있게끔하여 개발 -> 유지보수성, 확장성, 유연성 증가
  - 중복 코딩 문제점 해결
- 파생 패턴
  - MVP, MVVM, Viper, Clean Arichitecture, Flux, Redux 등...
  - MVP : Model + View + Presenter
    - 구조 
    
      ![ex_screenshot](/res/mvp.png)
      - Model : 애플리케이션에서 사용되는 데이터와 그 데이터를 처리하는 부분
      - View : 사용자에게 보여지는 UI 부분
      - Presenter : View에서 요청한 정보로 Model을 가공하여 View에 전달해주는 ㅂ ㅜ분
    - 동작 순서
      - 사용자 Action이 View를 통해 들어옴
      - View는 데이터를 Presenter에 요청
      - Presenter는 Model에게 데이터 요청
      - Model은 Presenter에서 요청받은 데이터를 응답
      - Presenter는 View에게 데이터를 응답
      - View는 Presenter가 응답한 데이터를 이용해 화면을 나타냄
    - 특징 
      - Presenter는 View와 Model 인스턴스를 가지고 있어 둘을 연결하는 접착제 역할을 수행 
      - Presenter와 View는 1:1 관계
    - 장단점
      - View와 Model의 의존성이 없다
      - View와 Presenter 사이의 의존성이 높다 -> 애플리케이션이 복잡해질 수록 의존성이 강해짐
  - MVVM : Model + View + View Model 
    - Model과 Viewe은 다른 패턴과 동일 
    - 구조
    
      ![ex_screenshot](/res/mvvm.png)
      - View Model : View를 표현하기 위해 만든 View Model, View를 나타내기 위한 데이터 처리를 수행
    - 동작 순서
      - 사용자 Action이 View를 통해 들어옴
      - View에 Action이 들어오면 Command 패턴으로 View Model에 Action 전달
      - View Model은 Model에게 데이터 요청
      - Model은 요청 받은 데이터 응답
      - View Model은 응답받은 데이터를 가공하여 저장
      - View는 View Model과 Data Binding하여 화면에 나타냄
    - 특징 
      - Command 패턴과 Data Binding을 사용하여 구현 (View와 View Model 간 의존성 해결)
      - View Model과 View는 1:n 관계
    - 장단점
      - View와 Model 사이 의존성이 없다
      - 각 부분이 독립적이기 때문에 모듈화 하여 개발 할 수 있다
      - View Model 설계가 쉽지 않다
5. promise  

6. myBatis vs sequalize 
- mybatis
  - 객체지향 언어인 자바의 관계형 데이터베이스 프로그래밍을 좀 더 쉽게 할 수 있게 도와주는 개발 프레임워크
  - java는 jdbc api를 제공해주지만, jdbc를 이용하면 1개 클래스에 반복된 코드가 존재, 한파일에 java언어, sql 언어가 있어 재사용성이 좋지않는 단점이 있음
  - Mybatis는 jdbc의 단점을 개선, 개발자가 작성한 SQL 명령어와 자바 객체를 매핑해주는 기능을 제공, 기존에 사용하던 SQL 명령어를 재사용한다.
  - JDBC를 통해 데이터베이스에 엑세스하는 작업을 캡슐화하고 일반 SQL 쿼리, 저장 프로 시저 및 고급 매핑 지원
  - JDBC 코드 및 매개 변수의 중복작업을 제거
  
  - 특징 
    - 한 두줄의 자바 코드로 DB 연동을 처리
    - SQL 명령어를 자바 코드에서 분리하여 XML 파일에 따로 관리 -> 간결성 유지보수성 향상
    - 복잡한 쿼리나 다이나믹한 쿼리에 강하다 (비슷한 쿼리는 남발하게되는 단점이 존재)
    - 수동적인 파라미터 설정과 쿼리 결과에 대한 맵핑 구문을 제거 가능
    - JDBC의 모든 기능을 MyBatis가 대부분 베공
 
- 마이바티스 구조

  ![ex_screenshot](/res/mybatis.png)
  - mybatis-config는 mybatis의 메인 환경 설정 파일 
    - 어떤 DBMS와 커넥션을 할지, 어떤 mapper 파일들이 있는지 알수 있다.
    - Mybatis는 mapper 파일에 있는 각 SQL 명령어들을 Map에 담아 저장하고 관리
- MyBatis Databases Aceess 구조

  ![ex_screenshot](/res/mybatis2.jpg)
- Mybatis API
  - SqlSessinFactoryBuilder 클래스 : build()메소드를 통해 mybatis-config를 로딩하여 SqlSessionFactory 객체 생성
  - SqlSessionFactory 클래스 : SqlSession 객체에 대한 팩토리 객체, openSession() 메소드를 통해 SqlSession 객체를 얻을 수 있다.
<pre><code>
  public class SqlSessionFactoryBean { 
    private static SqlSessionFactory sessionFactory = null;
    static {
       try {
        if (sessionFactory == null) {
            Reader reader = Resources.getResourceAsReader("mybatis-config.xml");
            sessionFactory = new SqlSessionFactoryBuilder().build(reader);
        }
      } catch (Exception e) {
          e.printStackTrace();
      }
  }
  public static SqlSession getSqlSessionInstance() {
      return sessionFactory.openSession();
  }
}
 </code></pre>
  - SqlSession 클래스 : Mapper XML에 등록된 SQL을 실행하기 위해 API를 제공
    - 핵심적인 역할을 하는 클래스로 SQL 실행, 트랜잭션 관리 수행
    - selectOne(String stmt, Object param)
    - selectList(String stmt, Object param)
    - insert(String stmt, Object param)
    - update(String stmt, Object param)
    - delete(String stmt, Object param)
  <pre><code>
    public class BoardDAO {
       private SqlSession mybatis;
       public BoardDAO() {
          mybatis = SqlSessionFactoryBean.getSqlSessionInstance();
       }
       public void insertBoard(BoardVO vo) {
           mybatis.insert("BoardDAO.insertBoard", vo);
           mybatis.commit();
       }
       public void updateBoard(BoardVO vo) {
          mybatis.update("BoardDAO.updateBoard", vo);
          mybatis.commit();
       } 
       public void deleteBoard(BoardVO vo) {
          mybatis.delete("BoardDAO.deleteBoard", vo);
          mybatis.commit();
       }
       public BoardVO getBoard(BoardVO vo) {
          return (BoardVO) mybatis.selectOne("BoardDAO.getBoard", vo);
       } 
       public List<BoardVO> getBoardList(BoardVO vo) {
          return mybatis.selectList("BoardDAO.getBoardList", vo);
       } 
     }
  </code></pre>
- Mybatis 주요 컴포넌트 

  ![ex_screenshot](/res/mybatis3.png)

- sequailize
  - node.js에서 mysql을 사용할 때 raw Query문을 사용하지 않고 더욱 쉽게 다룰 수 있도록 도와주는 라이브러리
  - ORM(Object-Relational Mapping)로 분류
  - raw Query문을 사용하지 않고 자바스크립트를 이용해서 mysql을 사용
  - Node.js 기반의 ORM으로 Promise 문법을 사용
  - sequelize-cli : sequelize를 효율적으로 사용하기 위해 몇개의 폴더와 파일(스켈레톤)을 생성해줌
  <pre><code>
    npm install sequelize
    npm install mysql2
    npm install -g sequelize-cli
    sequelize init
  </code></pre>
    - config/config.json : sequelize를 사용하기 위해 환경을 설정하는 부분
      <pre><code>
        {
          "development": {
          "username": "root",
          "password": "비밀번호를 입력해주세요.",
          "database": "clitest",
          "host": "127.0.0.1",
          "dialect": "mysql",
          "operatorsAliases": false
        },
          ...
      }
      </code></pre>
    - model/index.js : model을 정의한 js 파일들을 모아놓은 폴더, Model을 정의하고 관계를 설정
      - /config/config.json 파일의 설정 값을 읽어 sequelize 생성
       - models 폴더 아래 존재하는 js파일 모두 로딩
       - db 객체에 Model을 정의하여 반환 
    - 실습 해보기!!!!
7. JPA
-  ORM(Object-relational mapping, 객체 관계 매핑)
  - 객체는 객체대로 설계하고, 관계형 DB는 관계형 DB대로 설계한다
  - ORM 프레임워크가 중간에서 매핑해줌
- JPA(Java Persistence API)
  - EJB
    - 과거 자바 표준이자 ORM
    - 코드가 매우 지저분 하며 API의 복잡성이 높다(interface를 많이 구현해야함)
    - 속도가 느리다
  - JPA
    - 현재 자바 진영의 ORM 표준으로 인터페이스의 모음
      - 실제로 동작하는 것은 아니다
      - JPA 인터페이스를 구현한 대표적 오픈 소스 -> Hibernate
- JPA 동작 과정
  - JPA는 애플리케이션과 JDBC 사이에서 동작
    - 개발자가 JPA 사용하면, JPA 내부에서 JDBC API를 사용하여 SQL을 호출하여 DB와 통신
    
    ![ex_screenshot](/res/jpa.png)
  - 저장 과정
 
    ![ex_screenshot](/res/jpa2.png)
    - 개발자는 JPA에 객체를 넘기고 JPA가 객체 엔티티 분석 -> INSERT SQL 생성 -> JDBC API 사용하여 SQL을 DB에 날린다.
  - 조회 과정
    ![ex_screenshot](/res/jpa3.png)
    - 개발자는 객체의 PK값을 JPA에 넘김
    - JPA는 엔티티의 매핑정보를 바탕으로 적절한 SELECT SQL 생성 -> JDBC API를 사용하여 SQL을 DB에 날림
    - DB로 부터 결과를 받아 객체에 모두 매핑힌다
  - 쿼리를 JPA가 만들어 주기 때문에 Object왈 RDB간의 패러다임 불일치를 해결할 수 있다.
- JPA 특징 
  - 데이터를 객체지향적으로 관리 할 수 있어 개발자는 비즈니스 로직에 집중할 수 있고 객체지향 개발이 가능
  - 자바 객체와 DB 테이블 사이 매핑 설정을 통해 SQL을 생성
  - 객체를 통해 쿼리를 작성할 수 있는 JPQL(Java Persistenece Query Lanaguage)를 지원
  - JPA는 성능 향상ㅇ르 위해 지연로딩, 즉시로딩과 같은 몇가지 기법을 제공 -> 잘 활용하면 SQL을 직접 사용하는 것과 유사한 성능을 얻을 수 있다.
- JPA를 사용해야 하는 이유
  - SQL 중심적인 개발에서 객체 중심으로 개발 
  - 생산성 
    - JPA를 마치 Java Collection에 데이터를 넣었다 빼는 것처럼 사용할 수 있게 만든 것
    - 간단한 CRUD
  - 유지보수 
    - 필드만 추가하고 SQL은 JPA가 처리하기에 손댈 것이 없다
  - Object와 RDB간 패러다임 불일치 해결
  - JPA의 성능 최적화 기능 
    - 1차 캐시와 동일성 보장 - 캐싱 가능 
    - 트랜잭션을 지원하는 쓰기 지연 - 버퍼링 기능
      - JDBC Batch 기능을 사용해서 한번에 SQL을 전송
    - 지연 로딩(Lazy Loading)
      - 지연 로딩 : 객체가 실제로 사용될 때 로딩하는 전략
      - 즉시 로딩 : JOIN SQL로 한 번에 연관된 객체까지 미리 조회하는 전략 

- JPA, Hibernate, Spring Data JPA 차이점
  - JPA : 자바 애플리케이션에서 관계형 데이터베이스를 사용하는 방식을 정의한 인터페이스
  - Hibernate : JPA의 구현체 
  - Spring Data JPA : JPA를 쓰기 편하게 만들어 놓은 모듈 
  
  ![ex_screenshot](/res/jpa4.png)
  
8. REST API
- REST(Representational State Transfer) : HTTP 기반으로 필요한 자원에 접근하는 방식을 정해놓은 아키텍쳐
  - 자원 : 저장된 데이터, 이미지, 동영사, 문서 등과 같은 파일, 서비스르 모두 포함
  - HTTP URI를 통해 자원을 명시하고, HTTP Method를 통해 해당 자원에 대한 CRUD를 적용하는 
- REST API는 REST를 통해 서비스 API를 구현한 것
- REST 4가지 속성 
  - 서버에 있는 모든 Resource는 각 resource 당 클라이언트가 바로 접근할 수 있는 고유 URI가 존재
  - 모든 요청은 클라이언트가 요청시 필요한 정보를 주기 때문에 서버에는 세션 정보를 보관할 필요없음
  - HTTP 메소드를 사용 -> 모든 resource는 일반적으로 http 인터페이스인 GET, POST, PUT, DELETE 4개 메소드로 접근 되어야한다.
  - 서비스 내에 하나의 resource가 주변에 연관된 리소스들과 연결되어 표현이 되어야한다
- Resource
  - REST에서 접근시 URI(자원의 위치를 나타내는 일종의 식별자)로 접근
  - '/'의 쓰임새 
    - 계층 관계를 나타내는데 사용
    - URI의 마지막 문자로 슬래시를 포함하지 않음
  - URI를 이루는 resource들은 동사보다는 명사로 이루어져야한다
  - URI에서는 '_'보다 '-'을 권장
  - URI 경로에는 소문자가 적합
  - 파일확장자는 포함시키지 않는다 (Accept header를 사용하기)
- HTTP 메소드
  - POST / GET / PUT / DELETE
- Endpoint
  - 같은 URI들에 대해서도 다른 요청을 하게끔 구별해주는 항목
- 메시지
  - HTTP header와 body, 응답상태코드로 구성
  - header와 body에 포함된 메시지는 메시지를 처리하기 위한 충분한 정보를 포함
- Body 
  - 자원에 대한 정보를 전달 (데이터 포맷 : JSON/XML/사용자 정의 포맷)
- Header : HTTP 바디에 어떤 포맷으로 데이터가 담겨져 있는지 정의
  - 'Accept'항목으로 응답 HTTP 헤더는 'Content-type'으로 컨텐츠 타입을 설명
- 응답상태코드
- REST의 장단점
  - 장점
    - 언어와 플랫폼에 독립적이다
    - SOAP보다 개발이 쉽고 단순하다
    - REST가 지원하는 프레임워크나 언어등 도구들이 없어도 구현이 가능
    - 기존 웹 인프라를 사용가능 (HTTP를 그대로 사용하기 때문)
    - 서버와 클라이언트의 역할을 명확히 분리한다
    - Hypermedia API의 기본을 충실히 지키며 범용성을 보장
    - REST API 메시지가 의도하는 바를 명확하게 나타내므로 의도를 쉽게 파악 가능
  - 단점
    - Method 형태가 제한적이다
    - HTTP 프로토콜만 사용이 가능하다
    - P2P 통신 모델을 가정했기에 둘 이상을 대상으로하는 분산환경에는 유용하지 않다
    - 보안, 정책 등에 대한 표준이 없어 관리가 어렵고, 설계나 구현에 어려움을 갖는다
    - 구형 브라우저가 아직 제대로 지원해주지 못하는 부분 존재 (PUT, DELETE)
    
- REST 특징
  - Uniform : URI로 지정한 리소스에 대한 조작을 통일되고 한정적인 인터페이스로 수행하는 아키텍처 스타일
  - Stateless : 상태정보를 따로 저장하고 관리하지 않음, 요청만 단순히 처리
    - 서비스의 자유도가 높아지고 서버에 불필요한 정보를 관리하지 않으므로 구현이 단순해짐
  - Cacheble : 웹에사 사용하는 기존 인프라를 그대로 활용 가능, HTTP가 가진 캐싱 기능 적용 가능
  - Self-descriptiveness : REST API 메시지만 보고도 쉽게 이해할 수 있는 자체 표현 구조로 되어있음
  - Client-Server 구조 : 서버는 API 제공, 클라이언트는 사용자 인증, 컨텍스트 등을 직접관리하는 구조로 각 역할이 확실히 구분되어 있기에 개발할 내용이 명확해지고 서로 간 의존성이 줄어든다
  - 계층형 구조 : 보안, 로드 밸런싱, 암호화 계층을 추가해 구조상의 유연성을 줄 수 있다
    - PROXY, 게이트웨이 같은 네트워크 기반의 중간매체를 사용할 수 있다
    - 로드 밸런싱, 공유 캐시 등을 통해 확장성과 보안성을 향상시킬 수 있다
- REST API 특징
  - REST 기반으로 시스템을 분산해 확장성과 재사용성을 높여 유지보수 및 운용을 편리할게 할 수 있다
  - HTTP 표준을 기반으로 구현하므로, HTTP를 지원하느 프로그램 언어로 클라이언트, 서버를 구현할 수 있다
- RESTful
  - 'REST API'를 제공하는 웹서비스를 'RESTful'하다고 할 수 있다. (REST 원리를 따르는 시스템)
- REST가 필요한 이유
   - 애플리케이션 분리 및 통합
   - 다양한 클라이언트 등장
   - 멀티 플랫폼에 대한 지원을 위해 서비스 자원에 대한 아키텍쳐를 세우고 이용하는 방법을 모색한 결과 REST에 관심을 가짐

9. GraphQL
- SQL : 데이터베이스 시스템에 저장된 데이터를 효율적으로 가져오는 것이 목적, 주로 서버에서 호출
- GraphQL : 웹 클라이언트가 데이터를 서버로부터 효율적으로 가져오는 것이 목적, 주로 클라이언트에서 호출
- 서버사이드 gql 애플리케이션은 gql로 작성된 쿼리를 입력으로 받아 쿼리를 처리한 결과를 다시 클라이언트로 돌려줌
- 특정 데이터베이스, 플랫폼, 네트워크 방식에 종속적이지 않음

![ex_screenshot](/res/gql.png)

- REST API와 비교
  - REST API : URL, METHOD 등을 조합하기에 다양한 EndPoint 존재, Endpoint마다 데이터베이스 SQL 쿼리가 달라짐
  - GQL : 단 하나의 Endpoint가 존재, gql API는 불러오는 데이터의 종류를 쿼리 조합을 통해 결정, gql 스키마의 타입마다 데이터베이스 SQL 쿼리가 달라짐

  ![ex_screenshot](/res/gql2.png)
  ![ex_screenshot](/res/gql3.png)

- GraphQL의 구조
  - 쿼리/뮤테이션
    - 쿼리는 데이터를 읽는데 사용(R), 뮤테이션은 데이터를 변조(CUD)하는데 사용
  - 스키마/타입 
    <pre><code> 
      type Character {
        name: String!
        appearsIn: [Episode!]!
    }
    </code></pre>
     - 느낌표(!) : 필수 값, 스칼라 타입 : String,id, Int 등.., 대괄호 : 배열을 의미 등...
  - 리졸버(resolver)
    - gql에서 데이터를 가져오는 과정은 resolver가 담당하고 직접 구현해야한다.
    - 데이터 source의 종류에 상관없이 구현이 가능 (DB, 파일, http, SOAP활용 원격 데이터 등)
    - 각각의 필드마다 함수가 하나씩 존재하고 각각의 함수를 리졸버라고 한다
    - 연쇄적 리졸버 호출은 DBMS의 관계에 대한 쿼리를 매우 쉽고, 효율적으로 처리할 수 있다
- GraphQL의 장단점
  - 장점 
    - 클라이언트가 필요한 데이터만 반환할 수 있음
    - 1번의 호출로 원하는 데이터를 한번에 가져올 수 있음( REST API의 N+1 문제를 해결할 수 있음)
    - 확장이 용이하다
    - HTTP 요청 횟수를 줄일 수 있다
    - HTTP 응답의 size를 줄일 수 있다 
  - 단점
    - 백 엔드, 클라이언트 개발자 양쪽 다 러닝커브가 있음
    - 단순한 서비스에서 사용하기 복잡
    - 캐싱 기능 구현이 복잡 -> 대부분 언어에서 라이브러리로 제공함
    - 요청이 TEXT로 날라기기에 File 전송 등을 구현하기 어려움
    - 고정된 요청과 응답만 필요할 경우 Query로 인해 요청의 크기가 RESTful API의 경우보다 커짐
    - 재귀적 Query가 불가능 
    
10. GrqphQL과 RESTFUL
- GrqphQL
  - 서로 다른 모양의 다양한 요청들에 대해 응답할 수 있어야 할때
  - 대부분의 요청이 CRUD에 해당할 때
- RESTful
  - HTTP와 HTTPs에 의한 Caching을 잘 사용하고 싶을 때
  - File 전송 등 단순한 Text로 처리되지 않는 요청들이 있을 때
  - 요청의 구조가 정해져 있을 때 

11. Cookie vs Session
- HTTP 프로토콜의 특징 
  - 비연결지향 : 클라이언트가 request를 서버에 보내면, 서버는 클라이언트에게 response를 보내고 접속을 끊음
  - 상태정보 유지 안함(stateless) : 연결을 끊는 순간 통신이 끝나며 상태 정보는 유지하지 않음
- 쿠키 
  - 클라이언트 로컬에 저장되는 키와 값이 들어있는 작은 데이터 파일
  - 이름, 값, 만료날짜, 경로 정보가 들어있다
  - 일정시간 데이터를 저장할 수 있다
  - 클라이언트의 상태정보를 로컬에 저장했다 참조
  - 쿠키 프로세스
    - 브라우저 웹 페이지 접속
    - 클라이언트가 요청한 웹 페이지를 받으며 쿠키를 클라이언트 로컬에 저장
    - 클라이언트가 재 요청시 웹 페이지 요청과 함께 쿠키값 전송
    - 지속적으로 로그인 정보를 가진 것 처럼 사용
  - 클라이언트에 300개까지 쿠키 저장 가능, 하나의 도메인당 20개 값만 가질 수 있음
  - 하나의 쿠키값은 4KB 까지 저장
  - Response Header에 Set-Cookie 속성을 사용하면 클라이언트에 쿠키를 만들 수 있다
  - 사용자가 따로 요청하지 않아도 브라우저가 Request시에 Request Header를 넣어 자동으로 서버에 전송
- 세션
  - 일정 시간동안 같은 브라우저로 부터 들어오는 일련의 요구를 하나의 상태로 보고 그 상태를 유지하는 기술
  - 뒙 브라우저를 통해 웹 서버에 접속한 이후 브라우저를 종료할 때 까지 유지되는 상태
  - 클라이언트가 Reqeust를 보내면, 해당 서버의 엔진이 클라이언트에게 유일한 id를 부여 -> 세션ID
  - 세션 프로세스
    - 클라이언트가 서버에 접속 시 세션 ID 발급
    - 서버에서 클라이언트로 발급해준 세션 ID를 쿠키를 사용해 저장(JESSIONID)
    - 클라이언트는 다시 접속 시, 쿠키를 이용해 세션ID 값을 서버에 전달
    - 세션을 구별하기 위해 ID가 필요, ID만 쿠리를 이용해 저장 -> 쿠키는 자동으로 서버에 전송
- 쿠키와 세션을 사용하는 이유
  - HTTP 프로토콜의 특징이자 약점을 보완하기 위해 사용 
  - 서버와 클라이언트가 통신 할 때 연속적으로 이어지지 않고 한번 통신이 되면 끊어짐
  - 서버는 클라이언트가 누구인지 계속 인증을 해줘야한다 -> 쿠키와 세션이 해결방안
  - 클라이언트와 정보 유지를 하기 위해 사용하는 것이 쿠키와 세션
- 쿠키와 세션 차이
  - 저장위치 : 쿠키는 클라이언트에 파일로 저장 / 세션은 서버에 저장
  - 보안 
    - 쿠키는 클라이언트 로컬에 저장되기 때문에 변질되거나 request에서 스나이핑 당할 우려가 있어 보안에 취약
    - 세션은 쿠키를 이용해 sessionid만 저장하고 그것으로 구분해 서버에서 처리하기에 보안성이 좋다
  - 라이프 사이클
    - 쿠키도 만료시간이 있지만, 파일로 저장되기 때문에 브라우저 종료해도 계속 정보가 남아 있을 수 있다
    - 세션도 만료 시간 정할 수 있지만 브라우저가 종료되면 만료시간에 상관없이 삭제
  - 속도
    - 쿠키에 저아보가 있기 때문에 서버에 요청시 속도가 빠르다
    - 세션은 정보가 서버에 있기 때문에 처리가 요구되어 비교적 속도가 느리다
  - 저장 형식 
    - 쿠키 : text / 세션 : Object
  - 사용 자원 : 쿠키 : 클라이언트 리소스 / 세션 : 웹 서버 리소스 
  - 쿠키를 사용하는 이유 
    - 세션은 서버 자원을 사용하기 때문에 무분별하게 만들다보면 서버의 메모리가 감당할 수 없어질 수 있고 속도가 느려질 수 있다.
  
12. JWT(JSON Web Token)
- 웹 표준으로 두 개체에서 JSON객체를 사용하여 가볍고 자가수용적인 방식으로 정보를 안정성 있게 전달해줌
- 수많은 프로그래밍 언어에서 지원(Java, C, C++, Python, C#, JavaScript 등)
- 자가 수용적 
  - JWT는 필요한 모든 정보를 자체적으로 지니고 있다
  - 토큰에 대한 기본정보, 전달할 정보, 토큰이 검증됐다 증명해주는 signature를 포함
- 쉽게 전달 할 수 있다
  - 두 개체 사이에서 손쉽게 전달 가능, 웹 서버의 경우 HTTP 헤더에 넣거나 URL 파라미터로 전달 가능
- JWT가 사용되는 상황
  - 회원 인증(JWT를 사용하느 가장 흔한 시나리오)
    - 유저 로그인 -> 서버는 유저의 정보에 기반한 토큰을 발급하여 유저에게 전달
    - 유저가 서버에 요청을 할 때마다 JWT를 포함해 전달
    - 서버가 클라이언트에게 요청 받을 때 마다, 해당 토큰이 유효하고 인증됐는지 검증
    - 유저가 요청한 작업에 권한이 있는지 확인하고 작업을 처리
    - 유저가 요청시 토큰만 확인하면 되기에 세션 관리 필요 없음
  - 정보 교류
    - 두 개체 사이 안정성있게 정보를 교환하기 위해 좋은 방법
    - 정보가 sign이 되어있기 때문에 정보를 보낸이가 바뀌지 않았는지, 조작되지 않았는지 검증 가능
- JWT 구조
  - Header
    - typ : 토큰의 타입 지정
    - alg : 해싱 알고리즘 지정(보통 HMAC SHA256 or RSA 사용) -> 검증 시 signature 부분에서 사용
    <pre><code>
    {
      "typ" : "JWT",
      "alg" : "HS256"
    }
    </code></pre>
  - payload : 토큰에 담을 정보('한 조각'을 클레임(claim)이라고 부르며 name/value 한쌍으로 이루어짐)
    - 클레임 종류 : 등록된 클레임, 공개된 클레임, 비공개 클레임
    - 등록된 클레임 : 토큰에 대한 벙보들을 담기위해 정해진 클레임, 사용은 선택적
      - iss : 토큰 발급자
      - sub : 토큰 제목
      - aud : 토큰 대상자
      - exp : 토큰 만료시간
      - nbf : Not Before, 토큰의 활성 날짜 
      - iat : 토큰이 발급된 시간, 토큰의 age가 얼마나 되었는지 판단 가능
      - jti : JWT의 고유 식별자, 주로 중복적인 처리를 방지하기 위해 사용, 일회성 토큰에 사용하면 유용
    - 공개 클레임
      - 충돌이 방지된 이름을 가지고 있어야함
      - 클레임 이름을 URI 형식으로 짓는다.
    - 비공개 클레임
      - 클라이언트, 서버 협의하에 사용되는 클레임 이름들
    - 예제
    <pre><code>
      {
        "iss": "dong.com",
        "exp": "1485270000000",
        "https://dong.com/jwt_claims/is_admin": true,
        "userId": "11028373727102",
        "username": "dong"
      }
    </code></pre>
  - 서명(signature)
    - 헤더의 인코딩값, 정보의 인코딩값을 합친 후 주어진 비밀키로 해쉬하여 생성
    <pre><code>
      HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
    </code></pre>
- JWT 장점
  - 사용자 인증에 필요한 모든 정보를 토큰에 포함하기에 별도의 인증 저장소가 필요 없다
  - URL 파라키터와 헤더로 사용
  - 수평 스케일이 용이
  - 디버깅 및 관리가 용이
  - 트래픽에 대한 부담이 낮음
  - 내장된 만료
  - REST 서비스로 제공 가능
- JWT 단점
  - 클라이언트에 저장되어 DB에서 사용자 정보를 조작하더라도 토큰에 직접 적용할 수 없다
  - 비상태 애플리케이션에서 토큰은 거의 모든 요청에 전송 -> 트래픽 크기에 영향을 미칠 수 있다
  
13. Oauth 2.0
- 인증과 리소스에 대한 권한부여 기능 -> OAuth
- OAuth는 서버와 클라이언트 사이에 인증 완료하면 서버는 권한부여 결과로써 access token을 전송
- 클라이언트는 access token을 이용해 접근 및 서비스를 요청 할 수 있다
- 서버는 aceess token 기반으로 서비스와 권한을 확인하여 접근 허용여부 결정
- 결과 데이터를 클라이언트에게 보내줌
- 서버는 access token을 기반으로 클라이언트를 확인하여 서비스
- OAuth2.0 : 외부 서비스의 인증 및 권한부여를 관리하는 범용 프레임워크
  - OAuth 기반 서비스의 API를 호출 할때, HTTP 헤더에 access token을 포함하여 요청을 보냄
  - 서비스는 access token을 검사하면서 요청이 유효한지 판단하여 적절한 결과를 응답
- OAuth를 구성하고 있는 주요 4가지 객체
  - resource owner(자원 소유자) : protected resource에 접근하는 권한을 제공
  - resource server(자원 서버) : access token을 사용해서 요청을 수신할 때, 권한을 검증한 후 적절한 결과를 응답
  - client : resource owner의 protected resource에 접근을 요청하는 애플리케이션
  - authorization Server는 client가 성공적으로 access token을 발급받은 이후 resource owner를 인증하고 권한을 부여
- 간단한 권한 허가 절차

  ![ex_screenshot](/res/oauth.JPG)
  - client가 resource owner에게 권한 요청 
  - resource owner가 권한을 허가하면, client는 권한 증서를 발급 받음
    - authoriztion은 소유자가 자원에 접근할 수 있는 권한을 부여하였다는 확인증 
    - client가 access token을 얻어오는데 사용
    - authorization 4개 타입
      - Authorization Code : Client가 Resource Owner에게 직접 권한 부여를 요청하는 대신, Resource owner가 권한 서버에서 인증을 받고 권한을 허가, 허가 시 권한 코드가 발급되고 클라이언트에게 전달
        - 클라이언트는 코드를 서버에 보내주며 권한 허가를 받은 사실을 알리고  access token을 받게됨
      - Impicit : 권한 코드를 간소화한 절차
        - 권한 코드 방식에서 access token을 얻기기위해 권한 코드를 별도 발급하지 않고 access token이 바로 발급
      - Resorce Owner Password Credentials : 자원 소유자의 계정 아이디, 비밀번호 같은 계정 인증 정보가 access token을 얻기 위한 권한 증서로 사용
        - 계정정보를 애플리케이션에 직접 입력해야하므로 신뢰할 수 있어야함
        - access token을 얻은 후 리소스 요청을 위해 계정 인증정보를 클라이언트가 보관할 필요 없음
      - Client Credential : 클라이언트 인증 방식
        - 클라이언트가 관리하는 리소스에만 접근할 경우로 권한이 한정되어 있을 때 활용 가능
        - 클라이언트는 자기를 인증할 수 있는 정보를 권한 서버에 보내면서 access token을 요청
    - 권한 증서를 받은 클라이언트는 최종 목적인 access token을 권한 서버에 요청
    - 요청받은 권한 서버는 클라이언트가 보낸 권한 증서의 유효성을 검증
    - 유효하다면 access token 발급하고 결과를 클라이언트에게 알려줌
    - access token을 받은 클라이언트는 자원 서버에 자원을 요청
    - 요청 받은 자원 서버는 access token의 유효성을 검증하고 유효한 경우 요청을 처리
- Access and Refresh Token
  - Access token : 요청 절차를 정상적으로 종료한 클라이언트에게 발급
    - 보호된 자원에 접근할 때 권한 확인용으로 사용
    - 계정 인증에 필요한 형태들을 토큰으로 표현함으로써, 리소스 서버는 여러 인증 방식에 대응하지 않아ㅏ도 권한을 확일 할 수 있게됨.
  - Refresh token 
    - 사용하고 있던 access token이 유효기간 종료 등으로 만료될 경우 새로운 토큰을 얻을 때 사용
    - 권한 서버가 access token을 발급해주는 시점에 refresh token도 함께 발급하여 클라이언트에 알려줌
    - 전용 발급 절차 없이 미리 가지고 있을 수 있음
    - 권한 서버에만 활용되며 리소스 서버에는 전송되지 않음

- OAuth
  - 용어 및 개념
    - User : Service Provider에 계정을 가지고 있으며, Consumer앱을 이용하려는 사용자
    - Service Provider : OAuth를 사용하는 Open API를 제공하는 서비스
    - Protected Resource : Service Provider로부터 제공되어지는 API 자원들
    - Consumer : OAuth 인증을 사용해 Service Provider의 기능을 사용하려는 애플리케이션이나 웹 서비스
    - Consumer Key : Consumer가 Service Provider에게 자신을 식별하는 데 사용하는 키
    - Consumer Secret : Consumer Key의 소유권을 확립하기위해 Consumer가 사용하는 Secret
    - Request Token : Consumer가 Service Provider에게 접근 권한을 인증받기 위해 사용하는 값, 인증 완료후에는 Access Token으로 교환
    - Access Token : 인증 후 Consumer가 Service Provider의 자원에 접근하기 위한 키를 포함한 값
    - Token Secret : 주어진 토큰의 소유권을 인증하기 위해 소비자가 사용하는 Secret
  - OAuth의 WorkFlow
  
      ![ex_screenshot](/res/oauth2.png)
    - Consumer는 Service Provider로부터 Client key, Client Secret을 발급 받고 Service Provider에 API 사용할 것을 등록하고 Service Provider가 Consumer를 식별할 수 있게 해줌
    - Request Token 요청 시 Consumer의 정보, Signature 정보를 포함하여 Reqeust token 요청하고 발급받음
    - Request token값 받은 후 Consumer는 User를 Service Provider에 인증 사이트로 다이렉트 시키고, 유저는 Service Provider에 유저임을 인증
    - Consumer는 해당 유저가 인증되면 OAuth_token과 OAuth_cerifier를 넘겨준다
    - Consumer는 OAuth_token && OAuth_verifier를 받은 후 signature를 만들어 Access Token을 요청
    - Service Provider는 토큰과 서명들이 인증되었으면 Access Token을 Consumer에게 넘김
    - Access Token 및 서명정보를 통해 Service Provider에 Protected Resource에 접근 할 수 있게됨
  - OAutht 1.0과 2.0의 차이점
    - 인증 절차 간소화 : 기능의 단순화, 규모 확장성 지원, 디지털 서명 기반 -> https에 맡김
    - 용어 변경 : User -> Resource Owner ( 사용자)
                  Protected Resource -> Resource Server (REST API 서버)
                  Service Provider -> Authorization Server ( 인증 서버)
                  Consumer -> Client (third party 애플리케이션)
    - Resource Server와 Authorization Server 분리
      - Authorization Server의 역할을 명확히 함      
- 인증 종류
  - Authorization Code Grant
    - 일반적인 웹사이트에서 소셜로그이과 같은 인증을 받을 때 활용되는 방식 
    
    ![ex_screenshot](/res/acg.png)
    1. 클라이언트가 Redirect URL을 포함하여 Authorization Servere 인증 요청
    2. AuthorizationServer는 유저에게 로그인창을 제공하여 유저를 인증하게함.
    3. AuthorizationServer는 Authorization code를 클라이언트에게 제공
    4. Client는 코드를 Authorization Server에 Access Token을 요청
    5. Authorization 서버는 클라이언트에게 Access Token을 발급
    6. Access token을 이용하여 Resource server에 자원을 접근할 수 있게 된다
    7. 토큰 만료후 refresh token을 이용하여 토큰을 재발급
  - Implicit Grant
    - Public Client인 브라우저 기반 애플리케이션이나 모바일 애플리케이션에서 바로 Resource Server에 접근하여 사용할 수 있는 방식
    
    ![ex_screenshot](/res/oauth3.png)
    1. 클라이언트는 Authorization server에 인증 요청
    2. 유저는 Authorization server를 통해 인증
    3. Authorization server는 Access token을 포함하여 클라이언트의 Redirect url을 호출
    4. 클라이언트는 해당 Access token이 유요한지 Authoriziation server에 인증 요청
    5. 인증서버는 토큰이 유효하다면 토큰의 만기시간과 함께 리턴
    6. 클라이언트는 Resource server에 접근 가능
  - Resource Owner Password Credentials Grant
    - Client에 아이디/패스워드를 받아 직접 access token을 받아오는 방식
    - Client가 확실한 신용이 보장될 때 사용할 수 있는 방식
    
    ![ex_screenshot](/res/oauth4.png)
    1. 유저가 ID, Password 입력
    2. 클라이언트는 유저의 id, password와 클라이언트 정보를 넘김
    3. Authorization server는 Access toekn을 넘김
  - Client Credentials Grant
    - 애플리케이션이 Confidential Client일 때 id, secret을 가지고 인증하는 방식
    
    ![ex_screenshot](/res/oauth5.png)
    1. 클라이언트 정보를 Authorization server에 넘김
    2. Access Token을 Client에 전달
  - Device Code Grant
    - 브라우저가 없거나 입력이 제한된 장치에서 사용
  - Refresh Token Grant
    - 기존에 저장해둔 리프러시 토큰이 존재 시 access toekn 재발급 받을 필요가 있을 때 사용
    - 기존 access token은 만료 
    
14.Spring security + JWT + Oauth2 
- 기존 oauth2의 문제점
  - api 호출 시마다 access token이 유효한지 실제 oauth 서버를 통해 검증
  - oauth에서 해당 토큰 만료여부 등을 db에서 조회하고 새로 갱신 시 업데이트 수행
  - oauth 서버에 상당한 부담을 준다
  -> Claim 기반 토큰 사용하여 oauth서버의 부담을 줄여준다 (JWT)
