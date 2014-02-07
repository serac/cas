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
package org.jasig.cas.authentication.handler.support;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;

import org.jasig.cas.Message;
import org.jasig.cas.authentication.BasicCredentialMetaData;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.handler.NoOpPrincipalNameTransformer;
import org.jasig.cas.authentication.handler.PasswordEncoder;
import org.jasig.cas.authentication.handler.PlainTextPasswordEncoder;
import org.jasig.cas.authentication.handler.PrincipalNameTransformer;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.support.PasswordPolicyConfiguration;
import org.jasig.cas.util.Pair;

import javax.security.auth.login.AccountNotFoundException;
import javax.validation.constraints.NotNull;

/**
 * Abstract class to override supports so that we don't need to duplicate the
 * check for UsernamePasswordCredential.
 *
 * @author Scott Battaglia
 * @author Marvin S. Addison
 *
 * @since 3.0
 */
public abstract class AbstractUsernamePasswordAuthenticationHandler extends
    AbstractPreAndPostProcessingAuthenticationHandler {

    /**
     * PasswordEncoder to be used by subclasses to encode passwords for
     * comparing against a resource.
     */
    @NotNull
    private PasswordEncoder passwordEncoder = new PlainTextPasswordEncoder();

    @NotNull
    private PrincipalNameTransformer principalNameTransformer = new NoOpPrincipalNameTransformer();

    private PasswordPolicyConfiguration passwordPolicyConfiguration;

    /** {@inheritDoc} */
    @Override
    protected final HandlerResult doAuthentication(final Credential credential)
            throws GeneralSecurityException, PreventedException {
        final UsernamePasswordCredential userPass = (UsernamePasswordCredential) credential;
        if (userPass.getUsername() == null) {
            throw new AccountNotFoundException("Username is null.");
        }
        final String transformedUsername = this.principalNameTransformer.transform(userPass.getUsername());
        if (transformedUsername == null) {
            throw new AccountNotFoundException("Transformed username is null.");
        }
        final Pair<Principal, List<Message>> pair = authenticateUsernamePasswordInternal(
                transformedUsername,
                this.passwordEncoder.encode(userPass.getPassword()));
        return new HandlerResult(this, new BasicCredentialMetaData(credential), pair.getFirst(), pair.getSecond());
    }

    /**
     * Authenticates a username/password credential by an arbitrary strategy.
     *
     * @param username Non-null username produced by {@link #principalNameTransformer} acting on
     *                 {@link org.jasig.cas.authentication.UsernamePasswordCredential#getUsername()}.
     * @param encodedPassword Password to authenticate.
     *
     * @return Resolved principal and messages to display to user on authentication success.
     *
     * @throws GeneralSecurityException On authentication failure.
     * @throws PreventedException On the indeterminate case when authentication is prevented.
     */
    protected abstract Pair<Principal, List<Message>> authenticateUsernamePasswordInternal(
            String username, String encodedPassword)
            throws GeneralSecurityException, PreventedException;

    /**
     * Method to return the PasswordEncoder to be used to encode passwords.
     *
     * @return the PasswordEncoder associated with this class.
     */
    protected final PasswordEncoder getPasswordEncoder() {
        return this.passwordEncoder;
    }

    protected final PrincipalNameTransformer getPrincipalNameTransformer() {
        return this.principalNameTransformer;
    }

    protected final PasswordPolicyConfiguration getPasswordPolicyConfiguration() {
        return this.passwordPolicyConfiguration;
    }

    /**
     * Sets the PasswordEncoder to be used with this class.
     *
     * @param passwordEncoder the PasswordEncoder to use when encoding
     * passwords.
     */
    public final void setPasswordEncoder(final PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public final void setPrincipalNameTransformer(final PrincipalNameTransformer principalNameTransformer) {
        this.principalNameTransformer = principalNameTransformer;
    }

    public final void setPasswordPolicyConfiguration(final PasswordPolicyConfiguration passwordPolicyConfiguration) {
        this.passwordPolicyConfiguration = passwordPolicyConfiguration;
    }

    /**
     * @return True if credential is a {@link UsernamePasswordCredential}, false otherwise.
     */
    @Override
    public boolean supports(final Credential credential) {
        return credential instanceof UsernamePasswordCredential;
    }

    /**
     * Convenience method for returning an authentication success result with only a principal.
     *
     * @param principal Principal resolved on authentication success.
     *
     * @return Result containing principal and empty message list.
     */
    protected final Pair<Principal, List<Message>> newAuthnSuccessResult(final Principal principal) {
        return new Pair<Principal, List<Message>>(principal, Collections.<Message>emptyList());
    }

    /**
     * Convenience method for returning an authentication success result with principal and messages.
     *
     * @param principal Principal resolved on authentication success.
     * @param messages List of messages to be displayed to user.
     *
     * @return Result containing principal and message list.
     */
    protected final Pair<Principal, List<Message>> newAuthnSuccessResult(
            final Principal principal, final List<Message> messages) {
        return new Pair<Principal, List<Message>>(principal, messages);
    }
}
