package org.soasecurity.is.oauth.grant;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;

import org.apache.oltu.openidconnect.as.messages.IDTokenBuilder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;

/**
 * Change the class name as follows in <IS_HOME>/repository/conf/identity.xml
 * Copy the jar file to <IS_HOME>/repository/components/lib
 * <IDTokenCustomClaimsCallBackHandler>org.soasecurity.is.oauth.grant.IDTokenCustomClaims</IDTokenCustomClaimsCallBackHandler>
 */
public class IDTokenCustomClaims  implements CustomClaimsCallbackHandler {

    private static Log log = LogFactory.getLog(IDTokenCustomClaims.class);

    @Override
    public void handleCustomClaims(IDTokenBuilder builder, OAuthTokenReqMessageContext requestMsgCtx) {

        String userName = requestMsgCtx.getAuthorizedUser();
        String tenantDomain = MultitenantUtils.getTenantDomain(userName);
        userName = MultitenantUtils.getTenantAwareUsername(userName);
        RealmService realmService = OAuthComponentServiceHolder.getRealmService();
        UserStoreManager userStoreManager = null;

        String emailClaim = "http://wso2.org/claims/emailaddress";
        String roleClaim = "http://wso2.org/claims/role";
        String role = null;
        String email = null;

        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();

            // Get relevant values for the claim
            email = userStoreManager.getUserClaimValue(userName, emailClaim, null);
            role = userStoreManager.getUserClaimValue(userName, roleClaim, null);

        } catch (UserStoreException e) {
            log.error(e);
        }

        log.info("Email - " + email);
        log.info("Username - " + userName);
        log.info("Tenant Domain - " + tenantDomain);
        log.info("Role - "+role);

        // Add claims to the ID token
        builder.setClaim(emailClaim, email);
        builder.setClaim(roleClaim, role);


    }

}
