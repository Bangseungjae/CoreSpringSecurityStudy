package io.security.CoreSpringSecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();// 회원이 요청했던 정보를 담고있는 세션을 사용할 수 있다.

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        setDefaultTargetUrl("/");//인증 성공시 기본 경로
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {// 원래 요청했던 경로가 있다면 거기로 이동
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        }else{// 원래 요청했던 url이 없으면 기본 경로로
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }

    }
}
