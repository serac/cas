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
package org.jasig.cas.authentication.principal.ldap;


import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentialsToPrincipalResolver;

import org.springframework.beans.factory.InitializingBean;

/**
 * @author Marvin Addison
 * @author Misagh Moayyed
 * @since 4.0
 */
public class CredentialsToLdapAttributePrincipalResolver extends
             AbstractPersonDirectoryCredentialsToPrincipalResolver implements InitializingBean {
    /**
     * The CredentialsToPrincipalResolver that resolves the principal from the
     * request.
     */
    @NotNull
    private CredentialsToPrincipalResolver credentialsToPrincipalResolver =
                    new UsernamePasswordCredentialsToPrincipalResolver();

    /**
     * @param credentialsToPrincipalResolver The credentialsToPrincipalResolver
     * to set.
     */
    public final void setCredentialsToPrincipalResolver(
            final CredentialsToPrincipalResolver credentialsToPrincipalResolver) {
        this.credentialsToPrincipalResolver = credentialsToPrincipalResolver;
    }

    @Override
    public final boolean supports(final Credentials credentials) {
        return credentials instanceof UsernamePasswordCredentials;
    }

    @Override
    protected final String extractPrincipalId(final Credentials credentials) {
        final Principal principal = this.credentialsToPrincipalResolver.resolvePrincipal(credentials);

        if (principal == null) {
            log.warn("Initial principal could not be resolved from request via {}, returning null",
                    this.credentialsToPrincipalResolver.getClass().getSimpleName());
            return null;
        }

        log.debug("Resolved {}. Trying LDAP resolve now...", principal);
        return resolveLdapPrincipal(principal);
    }

    @Override
    public void afterPropertiesSet() throws Exception {}

    /**
     * Attempts to resolve the principal from back-end instance that may be
     * different from the existing configuration. This only serves as a template
     * method to allow for such use cases and by default, it will simply
     * assume that the resolved principal set by the
     * {@link #setCredentialsToPrincipalResolver(CredentialsToPrincipalResolver)}
     * should be used.
     *
     * @param principal resolved principal provided by
     * {@link #setCredentialsToPrincipalResolver(CredentialsToPrincipalResolver)}
     * @return the id of the resolved principal from ldap
     */
    protected String resolveLdapPrincipal(final Principal principal) {
        return principal.getId();
    }
}