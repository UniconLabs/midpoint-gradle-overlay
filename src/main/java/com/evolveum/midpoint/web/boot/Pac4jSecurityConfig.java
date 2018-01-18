package com.evolveum.midpoint.web.boot;

import com.evolveum.midpoint.security.api.UserProfileService;
import com.evolveum.midpoint.web.security.profile.MidpointProfileManager;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.engine.DefaultCallbackLogic;
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;
import org.pac4j.springframework.security.web.CallbackFilter;
import org.pac4j.springframework.security.web.SecurityFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Service;

import java.util.function.Function;

@Profile({"pac4j"})
@Configuration
@EnableWebSecurity
public class Pac4jSecurityConfig {
    @Value("${saml.keystorePath:/tmp/samlKeystore.jks}")
    private String keystorePath;

    @Value("${saml.keystorePassword:changeit}")
    private String keystorePassword;

    @Value("${saml.privateKeyPassword:changeit}")
    private String privateKeyPassword;

    @Value("${saml.identityProviderMetadataPath:/tmp/idp-metadata.xml}")
    private String identityProviderMetadataPath;

    @Value("${saml.maximumAuthenticationLifetime:3600}")
    private int maximumAuthenticationLifetime;

    @Value("${saml.serviceProviderEntityId}")
    private String serviceProviderEntityId;

    @Value("${saml.serviceProviderMetadataPath:/tmp/sp-metadata.xml}")
    private String serviceProviderMetadataPath;

    @Value("${saml.forceServiceProviderMetadataGeneration:false}")
    private boolean forceServiceProviderMetadataGeneration;

    @Value("${saml.callbackUrl}")
    private String callbackUrl;

    @Value("${saml.wantAssertionsSigned:true}")
    private boolean wantAssertionsSigned;

    @Bean
    public Config config() {
        final SAML2ClientConfiguration saml2ClientConfiguration = new SAML2ClientConfiguration();
        saml2ClientConfiguration.setKeystorePath(keystorePath);
        saml2ClientConfiguration.setKeystorePassword(keystorePassword);
        saml2ClientConfiguration.setPrivateKeyPassword(privateKeyPassword);
        saml2ClientConfiguration.setIdentityProviderMetadataPath(identityProviderMetadataPath);
        saml2ClientConfiguration.setMaximumAuthenticationLifetime(maximumAuthenticationLifetime);
        saml2ClientConfiguration.setServiceProviderEntityId(serviceProviderEntityId);
        saml2ClientConfiguration.setServiceProviderMetadataPath(serviceProviderMetadataPath);
        saml2ClientConfiguration.setForceServiceProviderMetadataGeneration(forceServiceProviderMetadataGeneration);
        saml2ClientConfiguration.setWantsAssertionsSigned(wantAssertionsSigned);

        final SAML2Client saml2Client = new SAML2Client(saml2ClientConfiguration);
        saml2Client.setName("Saml2Client");

        final Clients clients = new Clients(callbackUrl, saml2Client);

        final Config config = new Config(clients);
        return config;
    }

    @Service
    @Profile("pac4j")
    public static class MidpointProfileManagerFactory implements Function<J2EContext, ProfileManager> {
        @Autowired
        @Qualifier("userDetailsService")
        UserProfileService userProfileService;

        @Override
        public ProfileManager apply(J2EContext webContext) {
            return new MidpointProfileManager(webContext, userProfileService);
        }
    }

    @Configuration
    @Profile("pac4j")
    @Order(1)
    public static class Saml2WebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Autowired
        private Config config;

        @Autowired
        MidpointProfileManagerFactory midpointProfileManagerFactory;

        @Override
        protected void configure(final HttpSecurity http) throws Exception {
            final SecurityFilter filter = new SecurityFilter(config, "Saml2Client");

            ((DefaultSecurityLogic<Object, J2EContext>) filter.getSecurityLogic()).setProfileManagerFactory(midpointProfileManagerFactory);

            final CallbackFilter callbackFilter = new CallbackFilter(config);
            callbackFilter.setMultiProfile(true);
            ((DefaultCallbackLogic<Object, J2EContext>)callbackFilter.getCallbackLogic()).setProfileManagerFactory(midpointProfileManagerFactory);


            http.antMatcher("/**").addFilterBefore(callbackFilter, BasicAuthenticationFilter.class);
            http.authorizeRequests().anyRequest().fullyAuthenticated();

            http.addFilterBefore(filter, BasicAuthenticationFilter.class);
            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
            http.csrf().disable();
        }
    }
}
