package io.security.CoreSpringSecurity.security.configs;

import io.security.CoreSpringSecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.CoreSpringSecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.CoreSpringSecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.CoreSpringSecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.CoreSpringSecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.CoreSpringSecurity.security.provider.AjaxAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Slf4j
@EnableWebSecurity
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    //AjaxAuthenticationProvider를 사용하도록 설정
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }

//    @Bean
//    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
//        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
//        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
//        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
//        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
//        return ajaxLoginProcessingFilter;
//    }

    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .antMatcher("/api/**")//ajax 인증은 특정 url에서 적용되도록 적용
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .antMatchers("/api/login").permitAll()
                .anyRequest().authenticated()//어떤 요청에도 설정클래스에 관련된 자원에 접근하도록 설정
//                .and()
//                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);//기본 필터 앞에 위치하는 필터로 설정
;
        http
                .exceptionHandling()
                        .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                                .accessDeniedHandler(ajaxAccessDeniedHandler());

        http.csrf().disable();

        customConfigureAjax(http);
    }

    private void customConfigureAjax(HttpSecurity http) throws Exception {
        http
                .apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                .failureHandlerAjax(ajaxAuthenticationFailureHandler())
                .setAuthenticationManager(authenticationManagerBean())
                .loginProcessingUrl("/api/login");
    }

    @Bean
    public AccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }
}
