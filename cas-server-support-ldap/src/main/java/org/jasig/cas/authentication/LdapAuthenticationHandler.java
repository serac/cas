/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.authentication;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.validation.constraints.NotNull;

import org.jasig.cas.Message;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.authentication.support.LdapAccountStateHandler;
import org.jasig.cas.util.Pair;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.AuthenticationResultCode;
import org.ldaptive.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LDAP authentication handler that uses the ldaptive <code>Authenticator</code> component underneath.
 * This handler provides simple attribute resolution machinery by reading attributes from the entry
 * corresponding to the DN of the bound user (in the bound security context) upon successful authentication.
 * Principal resolution is controlled by the following properties:
 *
 * <ul>
 *     <ol>{@link #setPrincipalIdAttribute(String)}</ol>
 *     <ol>{@link #setPrincipalAttributeMap(java.util.Map)}</ol>
 * </ul>
 *
 * @author Marvin S. Addison
 * @since 4.0
 */
public class LdapAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    /** Logger instance. */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /** Performs LDAP authentication given username/password. */
    @NotNull
    private final Authenticator authenticator;

    /** Component name. */
    @NotNull
    private String name = LdapAuthenticationHandler.class.getSimpleName();

    /** Name of attribute to be used for resolved principal. */
    private String principalIdAttribute;

    /** Flag indicating whether multiple values are allowed fo principalIdAttribute. */
    private boolean allowMultiplePrincipalAttributeValues = false;

    /** Mapping of LDAP attribute name to principal attribute name. */
    @NotNull
    protected Map<String, String> principalAttributeMap = Collections.emptyMap();

    /** List of additional attributes to be fetched but are not principal attributes. */
    @NotNull
    protected List<String> additionalAttributes = Collections.emptyList();

    /** Set of LDAP attributes fetch from an entry as part of the authentication process. */
    private String[] authenticatedEntryAttributes;

    /** Handles ldaptive response with account state information. */
    private LdapAccountStateHandler ldapAccountStateHandler;


    /**
     * Creates a new authentication handler that delegates to the given authenticator.
     *
     * @param  authenticator  Ldaptive authenticator component.
     */
    public LdapAuthenticationHandler(@NotNull final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * Sets the name of the LDAP principal attribute whose value should be used for the
     * principal ID.
     *
     * @param attributeName LDAP attribute name.
     */
    public void setPrincipalIdAttribute(final String attributeName) {
        this.principalIdAttribute = attributeName;
    }

    /**
     * Sets a flag that determines whether multiple values are allowed for the {@link #principalIdAttribute}.
     * This flag only has an effect if {@link #principalIdAttribute} is configured. If multiple values are detected
     * when the flag is false, the first value is used and a warning is logged. If multiple values are detected
     * when the flag is true, an exception is raised.
     *
     * @param allowed True to allow multiple principal ID attribute values, false otherwise.
     */
    public void setAllowMultiplePrincipalAttributeValues(final boolean allowed) {
        this.allowMultiplePrincipalAttributeValues = allowed;
    }

    /**
     * Sets the mapping of additional principal attributes where the key is the LDAP attribute
     * name and the value is the principal attribute name. The key set defines the set of
     * attributes read from the LDAP entry at authentication time. Note that the principal ID attribute
     * should not be listed among these attributes.
     *
     * @param attributeNameMap Map of LDAP attribute name to principal attribute name.
     */
    public void setPrincipalAttributeMap(final Map<String, String> attributeNameMap) {
        this.principalAttributeMap = attributeNameMap;
    }

    /**
     * Sets the list of additional attributes to be fetched from the user entry during authentication.
     * These attributes are <em>not</em> bound to the principal.
     * <p>
     * A common use case for these attributes is to support password policy machinery.
     *
     * @param additionalAttributes List of operational attributes to fetch when resolving an entry.
     */
    public void setAdditionalAttributes(final List<String> additionalAttributes) {
        this.additionalAttributes = additionalAttributes;
    }

    /**
     * Sets the ldaptive account state handler. If none is defined, password expiration policy support will be
     * disabled.
     *
     * @param handler Handler that examines ldaptive {@link AuthenticationResponse} for password policy support.
     */
    public void setLdapAccountStateHandler(final LdapAccountStateHandler handler) {
        this.ldapAccountStateHandler = handler;
    }

    @Override
    protected final Pair<Principal, List<Message>> authenticateUsernamePasswordInternal(
            final String username, final String encodedPassword)
            throws GeneralSecurityException, PreventedException {

        final AuthenticationResponse response;
        try {
            logger.debug("Attempting LDAP authentication for {}", username);
            final AuthenticationRequest request = new AuthenticationRequest(
                    username,
                    new org.ldaptive.Credential(encodedPassword),
                    this.authenticatedEntryAttributes);
            response = this.authenticator.authenticate(request);
        } catch (final LdapException e) {
            throw new PreventedException("Unexpected LDAP error", e);
        }
        logger.debug("LDAP response: {}", response);

        final List<Message> messageList;
        if (this.ldapAccountStateHandler != null) {
            logger.debug("Applying password policy to {}", response);
            messageList = this.ldapAccountStateHandler.handle(response);
        } else {
            messageList = Collections.emptyList();
        }
        if (response.getResult()) {
            return newAuthnSuccessResult(createPrincipal(username, response.getLdapEntry()), messageList);
        }

        if (AuthenticationResultCode.DN_RESOLUTION_FAILURE == response.getAuthenticationResultCode()) {
            throw new AccountNotFoundException(username + " not found.");
        }
        throw new FailedLoginException("Invalid credentials.");
    }

    /**
     * Creates a CAS principal with attributes if the LDAP entry contains principal attributes.
     *
     * @param username Username that was successfully authenticated which is used for principal ID when
     *                 {@link #setPrincipalIdAttribute(String)} is not specified.
     * @param ldapEntry LDAP entry that may contain principal attributes.
     *
     * @return Principal if the LDAP entry contains at least a principal ID attribute value, null otherwise.
     *
     * @throws LoginException On security policy errors related to principal creation.
     */
    protected Principal createPrincipal(final String username, final LdapEntry ldapEntry) throws LoginException {
        final String id;
        if (this.principalIdAttribute != null) {
            final LdapAttribute principalAttr = ldapEntry.getAttribute(this.principalIdAttribute);
            if (principalAttr == null || principalAttr.size() == 0) {
                throw new LoginException(this.principalIdAttribute + " attribute not found for " + username);
            }
            if (principalAttr.size() > 1) {
                if (this.allowMultiplePrincipalAttributeValues) {
                    logger.warn(
                            "Found multiple values for principal ID attribute: {}. Using first value={}.",
                            principalAttr,
                            principalAttr.getStringValue());
                } else {
                    throw new LoginException("Multiple principal values not allowed: " + principalAttr);
                }
            }
            id = principalAttr.getStringValue();
        } else {
            id = username;
        }
        final Map<String, Object> attributeMap = new LinkedHashMap<String, Object>(this.principalAttributeMap.size());
        for (String ldapAttrName : this.principalAttributeMap.keySet()) {
            final LdapAttribute attr = ldapEntry.getAttribute(ldapAttrName);
            if (attr != null) {
                logger.debug("Found principal attribute: {}", attr);
                final String principalAttrName = this.principalAttributeMap.get(ldapAttrName);
                if (attr.size() > 1) {
                    attributeMap.put(principalAttrName, attr.getStringValues());
                } else {
                    attributeMap.put(principalAttrName, attr.getStringValue());
                }
            }
        }
        return new SimplePrincipal(id, attributeMap);
    }

    @PostConstruct
    public void initialize() {
        final List<String> attributes = new ArrayList<String>();
        if (this.principalIdAttribute != null) {
            attributes.add(this.principalIdAttribute);
        }
        attributes.addAll(this.principalAttributeMap.keySet());
        attributes.addAll(this.additionalAttributes);
        this.authenticatedEntryAttributes = attributes.toArray(new String[attributes.size()]);
    }
}
