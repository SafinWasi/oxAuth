/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client;

import static org.gluu.oxauth.model.authorize.DeviceAuthorizationRequestParam.CLIENT_ID;
import static org.gluu.oxauth.model.authorize.DeviceAuthorizationRequestParam.SCOPE;
import static org.gluu.oxauth.model.authorize.DeviceAuthorizationResponseParam.DEVICE_CODE;
import static org.gluu.oxauth.model.authorize.DeviceAuthorizationResponseParam.EXPIRES_IN;
import static org.gluu.oxauth.model.authorize.DeviceAuthorizationResponseParam.INTERVAL;
import static org.gluu.oxauth.model.authorize.DeviceAuthorizationResponseParam.USER_CODE;
import static org.gluu.oxauth.model.authorize.DeviceAuthorizationResponseParam.VERIFICATION_URI;
import static org.gluu.oxauth.model.authorize.DeviceAuthorizationResponseParam.VERIFICATION_URI_COMPLETE;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.gluu.oxauth.model.util.Util;
import org.jboss.resteasy.client.jaxrs.ClientHttpEngine;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.json.JSONObject;

/**
 * Encapsulates functionality to make Device Authz request calls to an authorization server via REST Services.
 */
public class DeviceAuthzClient extends BaseClient<DeviceAuthzRequest, DeviceAuthzResponse> {

    private static final Logger LOG = Logger.getLogger(DeviceAuthzClient.class);

    /**
     * Construct a device authz client by providing an URL where the REST service is located.
     *
     * @param url The REST service location.
     */
    public DeviceAuthzClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {
        return HttpMethod.POST;
    }

    public DeviceAuthzResponse exec() {
        initClientRequest();
        return _exec();
    }

    @Deprecated
    public DeviceAuthzResponse exec(ClientHttpEngine engine) {
    	resteasyClient = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
    	webTarget = resteasyClient.target(getUrl());

        return _exec();
    }

    private DeviceAuthzResponse _exec() {
        try {
    //        clientRequest.setHttpMethod(getHttpMethod());
            Builder clientRequest = webTarget.request();

            clientRequest.header("Content-Type", request.getContentType());
            new ClientAuthnEnabler(clientRequest, requestForm).exec(getRequest());

            final String scopesAsString = Util.listAsString(getRequest().getScopes());

            if (StringUtils.isNotBlank(scopesAsString)) {
                requestForm.param(SCOPE, scopesAsString);
            }
            if (StringUtils.isNotBlank(getRequest().getClientId())) {
                requestForm.param(CLIENT_ID, getRequest().getClientId());
            }

            // Call REST Service and handle response
            clientResponse = clientRequest.buildPost(Entity.form(requestForm)).invoke();

            setResponse(new DeviceAuthzResponse(clientResponse));
            if (response.getEntity() != null) {
                JSONObject jsonObj = new JSONObject(response.getEntity());

                if (jsonObj.has(USER_CODE)) {
                    getResponse().setUserCode(jsonObj.getString(USER_CODE));
                }
                if (jsonObj.has(DEVICE_CODE)) {
                    getResponse().setDeviceCode(jsonObj.getString(DEVICE_CODE));
                }
                if (jsonObj.has(INTERVAL)) {
                    getResponse().setInterval(jsonObj.getInt(INTERVAL));
                }
                if (jsonObj.has(VERIFICATION_URI)) {
                    getResponse().setVerificationUri(jsonObj.getString(VERIFICATION_URI));
                }
                if (jsonObj.has(VERIFICATION_URI_COMPLETE)) {
                    getResponse().setVerificationUriComplete(jsonObj.getString(VERIFICATION_URI_COMPLETE));
                }
                if (jsonObj.has(EXPIRES_IN)) {
                    getResponse().setExpiresIn(jsonObj.getInt(EXPIRES_IN));
                }
            }

            return getResponse();
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            return null;
        } finally {
            closeConnection();
        }
    }
}