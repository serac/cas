---
layout: default
title: Maven Overlay Installation
---
CAS installation is a fundamentally source-oriented process, and we recommend a [Maven WAR overlay](http://maven.apache.org/plugins/maven-war-plugin/overlays.html) project to organize customizations such as component configuration and UI design. A simple Maven WAR overlay project is provided for reference and study:

[cas-maven-war-overlay]

The following list of CAS components are those most often customized by deployers:

1. Authentication handlers (i.e. AuthenticationHandler)
2. Storage backend (i.e. TicketRegistry)
3. View layer files (JSP/CSS)

The first two are controlled by modifying Spring XML configuration files under src/main/webapp/WEB-INF/spring-configuration, the latter by modifying JSP and CSS files under src/main/webapp/WEB-INF/view/jsp/default in the Maven WAR overlay project. Every aspect of CAS can be controlled by adding, removing, or modifying files in the overlay; it's also possible and indeed common to customize the behavior of CAS by adding third-party components that implement CAS APIs as Java source files or dependency references.

Once an overlay project has been created, the CAS servlet deployable (WAR file) must be built and subsequently deployed into a Java servlet container such as [Tomcat](http://tomcat.apache.org/whichversion.html). The following set of commands, issued from the Maven WAR overlay project root directory, provides a sketch of how to accomplish this on a Unix platform.

    mvn clean package
    cp target/cas.war $CATALINA_HOME/webapps/
    $CATALINA_HOME/bin/catalina.sh start

## Configuration Files
CAS configuration is controlled primarily by Spring XML context configuration files. At a minimum, every deployer must customize `deployerConfigContext.xml` and `cas.properties` by including them in the Maven WAR overlay, but there are other optional configuration files that may be included in the overlay for further customization or to provide additional features. The following exploded filesystem hierarchy shows how files should be organized in the overlay:

    ├── src
    │   ├── main
    │   │   └── webapp
    │   │       ├── WEB-INF
    │   │       │   ├── cas-servlet.xml
    │   │       │   ├── cas.properties
    │   │       │   ├── deployerConfigContext.xml
    │   │       │   ├── login-webflow.xml
    │   │       │   ├── restlet-servlet.xml
    │   │       │   ├── spring-configuration
    │   │       │   │   ├── applicationContext.xml
    │   │       │   │   ├── argumentExtractorsConfiguration.xml
    │   │       │   │   ├── auditTrailContext.xml
    │   │       │   │   ├── filters.xml
    │   │       │   │   ├── log4jConfiguration.xml
    │   │       │   │   ├── propertyFileConfigurer.xml
    │   │       │   │   ├── securityContext.xml
    │   │       │   │   ├── ticketExpirationPolicies.xml
    │   │       │   │   ├── ticketGrantingTicketCookieGenerator.xml
    │   │       │   │   ├── ticketRegistry.xml
    │   │       │   │   ├── uniqueIdGenerators.xml
    │   │       │   │   └── warnCookieGenerator.xml
    │   │       │   ├── unused-spring-configuration
    │   │       │   │   ├── clearpass-configuration.xml
    │   │       │   │   ├── lppe-configuration.xml
    │   │       │   │   └── mbeans.xml

It is common practice to exclude cas.properties from the overlay and place it at a well-known filesystem location outside the WAR deployable. In that case, `propertyFileConfigurer.xml` must be configured to point to the filesystem location of `cas.properties`. Generally, the Spring XML configuration files under `spring-configuration` are the most common configuration files, beyond `deployerConfigContext.xml`, to be included in an overlay. The supplementary Spring configuration files are organized into logically separate configuration concerns that are clearly indicated by the file name.

CAS uses Spring Webflow to drive the login process in a modular and configurable fashion; the `login-webflow.xml` file contains a straightforward description of states and transitions in the flow. Customizing this file is probably the most common configuration concern beyond component configuration in the Spring XML configuration files. See the [[Spring Webflow Customization Guide]] for a thorough description of the various CAS flows and discussion of common configuration points.

