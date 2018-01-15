package com.evolveum.midpoint.web.security.authentication;

import com.evolveum.midpoint.security.api.MidPointPrincipal;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.springframework.security.authentication.Pac4jAuthentication;
import org.pac4j.springframework.security.util.SpringSecurityHelper;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.LinkedHashMap;

public class MidpointPac4jAuthenticationToken extends AbstractAuthenticationToken implements Pac4jAuthentication {
    private final LinkedHashMap<String, CommonProfile> profiles;
    private final CommonProfile profile;
    private final MidPointPrincipal midPointPrincipal;

    public MidpointPac4jAuthenticationToken(final LinkedHashMap<String, CommonProfile> profiles, MidPointPrincipal midPointPrincipal) {
        super(SpringSecurityHelper.buildAuthorities(profiles));
        this.profiles = profiles;
        this.profile = ProfileHelper.flatIntoOneProfile(profiles).get();
        this.midPointPrincipal = midPointPrincipal;
        this.setAuthenticated(true);
    }

    @Override
    public LinkedHashMap<String, CommonProfile> getInternalProfilesMap() {
        return this.profiles;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.midPointPrincipal;
    }
}
