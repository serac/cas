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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.SearchExecutor;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchResult;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * @author Marvin Addison
 * @author Misagh Moayyed
 * @since 4.0
 */
public final class CredentialsToLdapAttributePrincipalResolver extends
                   AbstractPersonDirectoryCredentialsToPrincipalResolver implements InitializingBean {

    /** Username parameter used in the search filter. **/
    private String searchFilterUserNameParameter = "user";

    /** Map of directory attribute name to CAS attribute name. */
    private Map<String, String> attributeMapping = new HashMap<String, String>();

    /** Flag that indicates whether multiple search results are allowed for a given credential. */
    private boolean allowMultipleResults = false;

    /** Attribute that will be used for identifier in resolved principal. */
    @NotNull
    private final String userNameAttribute;

    /** Performs the LDAP search operation. */
    @NotNull
    private final SearchExecutor searchExecutor;

    /** Source of LDAP connections. */
    @NotNull
    private final ConnectionFactory connectionFactory;

    /**
     * The CredentialsToPrincipalResolver that resolves the principal from the
     * request.
     */
    @NotNull
    private CredentialsToPrincipalResolver credentialsToPrincipalResolver;

    /**
     * Creates a new instance with the requisite parameters.
     *
     * @param  cf  Source of LDAP connections for search operation.
     * @param  se  Executes the search operation.
     * @param  userAttribute  Attribute name in search result used for resolved principal identifier.
     */
    public CredentialsToLdapAttributePrincipalResolver(final ConnectionFactory connectionFactory, final SearchExecutor searchExecutor,
                                                       final String userAttribute) {
        this.connectionFactory = connectionFactory;
        this.searchExecutor = searchExecutor;
        this.userNameAttribute = userAttribute;
    }

    /** The name of the username parameter in the search filter expression. */
    public void setSearchFilterUserNameParameter(final String param) {
        this.searchFilterUserNameParameter = param;
    }

    /**
     * Sets whether to allow multiple search results for a given credential.
     * This is false by default, which is sufficient and secure for more deployments.
     * Setting this to true may have security consequences.
     *
     * @param  allowMultiple  True to allow multiple search results in which case the first result
     *                        returned is used to construct the principal, or false to indicate that
     *                        a runtime exception should be raised on multiple search results.
     */
    public void setAllowMultipleResults(final boolean allowMultiple) {
        this.allowMultipleResults = allowMultiple;
    }

    /**
     * Sets the mapping of directory attribute name to CAS attribute name.
     *
     * @param  mapping  Attribute name mapping.  Keys are LDAP directory attribute names and
     *                  values are corresponding CAS attribute names.
     */
    public void setAttributeMapping(final Map<String, String> mapping) {
        this.attributeMapping = mapping;
    }

    /**
     * @param credentialsToPrincipalResolver The credentialsToPrincipalResolver
     * to set.
     */
    public void setCredentialsToPrincipalResolver(final CredentialsToPrincipalResolver credentialsToPrincipalResolver) {
        this.credentialsToPrincipalResolver = credentialsToPrincipalResolver;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(searchExecutor.getSearchFilter(), "SearchExecutor#searchFilter cannot be null.");
        final String filterString = searchExecutor.getSearchFilter().getFilter();
        Assert.notNull(filterString, "SearchExecutor#searchFilter#filter cannot be null.");

        /** User name placeholder in LDAP search filter expression. */
        final String userPlaceHolder = String.format("{%s}", this.searchFilterUserNameParameter);

        if (!filterString.contains(userPlaceHolder)) {
            throw new IllegalArgumentException("Search filter expression must container user name placeholder "
                                                + userPlaceHolder);
        }
    }

    @Override
    public boolean supports(final Credentials credentials) {
        return credentials instanceof UsernamePasswordCredentials;
    }

    @Override
    protected String extractPrincipalId(final Credentials credentials) {
        final Principal principal = this.credentialsToPrincipalResolver.resolvePrincipal(credentials);

        if (principal == null) {
            log.warn("Initial principal could not be resolved from request, returning null");
            return null;
        }

        log.debug("Resolved {}. Trying LDAP resolve now...", principal);

        final Principal ldapPrincipal = resolveFromLDAP(principal);

        if (ldapPrincipal == null) {
            log.info("Initial principal {} was not found in LDAP, returning null", principal.getId());
            return null;
        }

        log.debug("Resolved {} to {}", principal, ldapPrincipal);
        return ldapPrincipal.getId();
    }

    private Principal resolveFromLDAP(final Principal resolvedPrincipal) {
        final SearchResult result;
        try {
            log.debug("Attempting to resolve LDAP principal for {}.", resolvedPrincipal);

            final Set<String> attributesToReturn = new HashSet<String>(this.attributeMapping.keySet());
            attributesToReturn.add(userNameAttribute);
            final String[] attrs = attributesToReturn.toArray(new String[]{});

            final Response<SearchResult> response = searchExecutor.search(connectionFactory,
                    filterWithParams(resolvedPrincipal), attrs);
            log.debug("LDAP response: {}", response);
            result = response.getResult();
        } catch (final LdapException e) {
            log.error("LDAP error resolving principal from {}.", resolvedPrincipal, e);
            return null;
        }
        if (result.getEntries().size() > 1 && !allowMultipleResults) {
            throw new IllegalStateException("Multiple search results found but not allowed.");
        }
        final Principal ldapPrincipal;
        if (result.getEntries().isEmpty()) {
            log.debug("No results found for {}.", resolvedPrincipal);
            ldapPrincipal = null;
        } else {
            ldapPrincipal = principalFromEntry(result.getEntry());
        }
        log.debug("Resolved principal {}", ldapPrincipal);
        return ldapPrincipal;
    }

    /**
     * Creates a CAS principal from an LDAP entry.
     *
     * @param  entry  LDAP entry.
     *
     * @return  Resolved CAS principal.
     */
    private Principal principalFromEntry(final LdapEntry entry) {
        final LdapAttribute nameAttribute = entry.getAttribute(userNameAttribute);
        if (nameAttribute == null) {
            log.warn("Username attribute {} not found on {}; returning null principal.", userNameAttribute, entry);
            return null;
        }
        final String id = nameAttribute.getStringValue();
        final Map<String, Object> attributes = new HashMap<String, Object>(entry.getAttributes().size());
        Object value;
        for (LdapAttribute attribute : entry.getAttributes()) {
            if (userNameAttribute.equals(attribute.getName())) {
                continue;
            }
            log.debug("Resolving LDAP attribute [{}]", attribute.getName());
            if (attribute.size() == 1) {
                if (attribute.isBinary()) {
                    value = attribute.getBinaryValue();
                } else {
                    value = attribute.getStringValue();
                }
            } else {
                if (attribute.isBinary()) {
                    value = attribute.getBinaryValues();
                } else {
                    value = attribute.getStringValues();
                }
            }
            attributes.put(mapAttributeName(attribute.getName()), value);
        }
        return new SimplePrincipal(id, attributes);
    }

    /**
     * Maps an LDAP attribute name onto a CAS attribute name.
     *
     * @param  ldapName  LDAP attribute name.
     *
     * @return  Mapped name if a mapping exists for the given attribute, otherwise the original name.
     */
    private String mapAttributeName(final String ldapName) {
        final String localName = attributeMapping.get(ldapName);
        return localName != null ? localName : ldapName;
    }

    /**
     * Constructs a new search filter using {@link SearchExecutor#searchFilter} as a template and
     * the username from the credential as a parameter.
     *
     * @param  credentials  Source of username for LDAP search query.
     *
     * @return  Search filter with parameters applied.
     */
    private SearchFilter filterWithParams(final Principal principal) {
        final SearchFilter filter = new SearchFilter();
        filter.setFilter(searchExecutor.getSearchFilter().getFilter());
        filter.setParameter(this.searchFilterUserNameParameter, principal.getId());
        return filter;
    }
}
