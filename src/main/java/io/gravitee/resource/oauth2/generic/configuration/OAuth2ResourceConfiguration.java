/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.oauth2.generic.configuration;

import io.gravitee.resource.api.ResourceConfiguration;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2ResourceConfiguration implements ResourceConfiguration {

    private String authorizationServerUrl;

    private String introspectionEndpoint;

    private boolean useSystemProxy;

    private String introspectionEndpointMethod;

    private String userInfoEndpoint;

    private String userInfoEndpointMethod;

    private String clientId;

    private String clientSecret;

    private boolean useClientToken;

    private String clientToken;

    private boolean useClientAuthorizationHeader;

    private String clientAuthorizationHeaderName;

    private String clientAuthorizationHeaderScheme;

    private boolean tokenIsSuppliedByQueryParam;

    private String tokenQueryParamName;

    private boolean tokenIsSuppliedByHttpHeader;

    private String tokenHeaderName;

    private boolean tokenIsSuppliedByFormUrlEncoded;

    private String tokenFormUrlEncodedName;

    private String scopeSeparator;

    private String userClaim;

    public String getAuthorizationServerUrl() {
        return authorizationServerUrl;
    }

    public void setAuthorizationServerUrl(String authorizationServerUrl) {
        this.authorizationServerUrl = authorizationServerUrl;
    }

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public void setIntrospectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }

    public boolean isUseSystemProxy() {
        return useSystemProxy;
    }

    public void setUseSystemProxy(boolean useSystemProxy) {
        this.useSystemProxy = useSystemProxy;
    }

    public String getIntrospectionEndpointMethod() {
        return introspectionEndpointMethod;
    }

    public void setIntrospectionEndpointMethod(String introspectionEndpointMethod) {
        this.introspectionEndpointMethod = introspectionEndpointMethod;
    }

    public boolean getUseClientToken() {
        return useClientToken;
    }

    public void setUseClientToken(boolean useClientToken) {
        this.useClientToken = useClientToken;
    }

    public String getClientToken() {
        return clientToken;
    }

    public void setClientToken(String clientToken) {
        this.clientToken = clientToken;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public boolean isUseClientAuthorizationHeader() {
        return useClientAuthorizationHeader;
    }

    public void setUseClientAuthorizationHeader(boolean useClientAuthorizationHeader) {
        this.useClientAuthorizationHeader = useClientAuthorizationHeader;
    }

    public String getClientAuthorizationHeaderName() {
        return clientAuthorizationHeaderName;
    }

    public void setClientAuthorizationHeaderName(String clientAuthorizationHeaderName) {
        this.clientAuthorizationHeaderName = clientAuthorizationHeaderName;
    }

    public String getClientAuthorizationHeaderScheme() {
        return clientAuthorizationHeaderScheme;
    }

    public void setClientAuthorizationHeaderScheme(String clientAuthorizationHeaderScheme) {
        this.clientAuthorizationHeaderScheme = clientAuthorizationHeaderScheme;
    }

    public boolean isTokenIsSuppliedByQueryParam() {
        return tokenIsSuppliedByQueryParam;
    }

    public void setTokenIsSuppliedByQueryParam(boolean tokenIsSuppliedByQueryParam) {
        this.tokenIsSuppliedByQueryParam = tokenIsSuppliedByQueryParam;
    }

    public String getTokenQueryParamName() {
        return tokenQueryParamName;
    }

    public void setTokenQueryParamName(String tokenQueryParamName) {
        this.tokenQueryParamName = tokenQueryParamName;
    }

    public boolean isTokenIsSuppliedByHttpHeader() {
        return tokenIsSuppliedByHttpHeader;
    }

    public void setTokenIsSuppliedByHttpHeader(boolean tokenIsSuppliedByHttpHeader) {
        this.tokenIsSuppliedByHttpHeader = tokenIsSuppliedByHttpHeader;
    }

    public String getTokenHeaderName() {
        return tokenHeaderName;
    }

    public void setTokenHeaderName(String tokenHeaderName) {
        this.tokenHeaderName = tokenHeaderName;
    }

    public boolean isTokenIsSuppliedByFormUrlEncoded() {
        return tokenIsSuppliedByFormUrlEncoded;
    }

    public void setTokenIsSuppliedByFormUrlEncoded(boolean tokenIsSuppliedByFormUrlEncoded) {
        this.tokenIsSuppliedByFormUrlEncoded = tokenIsSuppliedByFormUrlEncoded;
    }

    public String getTokenFormUrlEncodedName() {
        return tokenFormUrlEncodedName;
    }

    public void setTokenFormUrlEncodedName(String tokenFormUrlEncodedName) {
        this.tokenFormUrlEncodedName = tokenFormUrlEncodedName;
    }

    public String getUserInfoEndpoint() {
        return userInfoEndpoint;
    }

    public void setUserInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public String getUserInfoEndpointMethod() {
        return userInfoEndpointMethod;
    }

    public void setUserInfoEndpointMethod(String userInfoEndpointMethod) {
        this.userInfoEndpointMethod = userInfoEndpointMethod;
    }

    public String getScopeSeparator() {
        return scopeSeparator;
    }

    public void setScopeSeparator(String scopeSeparator) {
        this.scopeSeparator = scopeSeparator;
    }

    public String getUserClaim() {
        return userClaim;
    }

    public void setUserClaim(String userClaim) {
        this.userClaim = userClaim;
    }
}
