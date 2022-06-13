package io.security.CoreSpringSecurity.security.voter;

import io.security.CoreSpringSecurity.security.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    /**
     *
     * @param authentication - 인증정보이다.(사용자의 정보)
     * @param object - request 요청 정보이다.(Invocation)
     * @param attributes - 권한 정보이다.
     * @return - 인가의 통과 정보를 반환한다.
     */
    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {


        // ip주소를 얻어온다.
        WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();

        List<String> accessIpList = securityResourceService.getAccessIpList();
        int result = ACCESS_DENIED;
        for (String ipAddress : accessIpList) {
            if (remoteAddress.equals(ipAddress)) {
                return ACCESS_ABSTAIN; // ACCESS_GRANTED를 주면 그 자원에  바로 접근하게 된다 그래서 "ACCESS_ABSTAIN"를 준다.
                // IP는 접근이 되도 그 사용이 사용이 가능한지 그 심의는 계속 되도록 한다.
            }
        }

        //IP가 허용이 안되면 바로 예외를 날려서 자원에 접근이 안되게 한다.
        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invalid IpAddress");
        }

        return result;
    }
}
