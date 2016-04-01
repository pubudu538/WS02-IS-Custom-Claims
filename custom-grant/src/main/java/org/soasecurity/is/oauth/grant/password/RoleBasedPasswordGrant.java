/*
 * Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.soasecurity.is.oauth.grant.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;

/**
 *  Modified version of default password grant type
 */
public class RoleBasedPasswordGrant extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(RoleBasedPasswordGrant.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        //  default password validation
        boolean authorized =  super.authorizeAccessDelegation(tokReqMsgCtx);

        // additional check for role based
        if(authorized) {

            String username = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getResourceOwnerUsername();

            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            RealmService realmService = OAuthComponentServiceHolder.getRealmService();
            UserStoreManager userStoreManager = null;
            try {
                int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();

                String[] roles = userStoreManager.getRoleListOfUser(MultitenantUtils.getTenantAwareUsername(username));

                for(String role : getAuthorizedRoles()){
                    if((new ArrayList<String>(java.util.Arrays.asList(roles))).contains(role)){
                        return true;
                    }
                }

            } catch (UserStoreException e) {
                log.error(e);
            }
        }

        return false;
    }


    /**
     * Retrieve authorized roles.  This can be read from configuration file.
     *
     * @return
     */
    private List<String> getAuthorizedRoles() {

        List<String> roles = new ArrayList<String>();

        // JUST FOR TESTING
        roles.add("TestRole");
        return roles;
    }
}
