package com.evolveum.midpoint.web.security.profile;

import com.evolveum.midpoint.security.api.MidPointPrincipal;
import com.evolveum.midpoint.security.api.UserProfileService;
import com.evolveum.midpoint.util.exception.ObjectNotFoundException;
import com.evolveum.midpoint.util.exception.SchemaException;
import com.evolveum.midpoint.web.security.authentication.MidpointPac4jAuthenticationToken;
import org.pac4j.core.authorization.authorizer.Authorizer;
import org.pac4j.core.authorization.authorizer.IsFullyAuthenticatedAuthorizer;
import org.pac4j.core.authorization.authorizer.IsRememberedAuthorizer;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.saml.profile.SAML2Profile;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.LinkedHashMap;
import java.util.List;

public class MidpointProfileManager extends ProfileManager<CommonProfile> {
    private static final Authorizer<CommonProfile> IS_REMEMBERED_AUTHORIZER = new IsRememberedAuthorizer<>();

    private static final Authorizer<CommonProfile> IS_FULLY_AUTHENTICATED_AUTHORIZER = new IsFullyAuthenticatedAuthorizer<>();

    UserProfileService userProfileService;

    public MidpointProfileManager(WebContext context) {
        this(context, null);
    }

    public MidpointProfileManager(WebContext context, UserProfileService userProfileService) {
        super(context);
        this.userProfileService = userProfileService;
    }

    @Override
    public void save(boolean saveInSession, CommonProfile profile, boolean multiProfile) {
        super.save(saveInSession, profile, multiProfile);

        final LinkedHashMap<String, CommonProfile> profiles = retrieveAll(saveInSession);
        if (profiles != null && profiles.size() > 0) {
            final List<CommonProfile> listProfiles = ProfileHelper.flatIntoAProfileList(profiles);
            try {
                if (IS_FULLY_AUTHENTICATED_AUTHORIZER.isAuthorized(null, listProfiles) || IS_REMEMBERED_AUTHORIZER.isAuthorized(null, listProfiles)) {
                    SAML2Profile saml2Profile = (SAML2Profile) profiles.get("Saml2Client");
                    MidPointPrincipal principal = this.userProfileService.getPrincipal((String) saml2Profile.getAttribute("uid", List.class).get(0));
                    SecurityContextHolder.getContext().setAuthentication(new MidpointPac4jAuthenticationToken(profiles, principal));
                }
            } catch (final HttpAction e) {
                throw new TechnicalException(e);
            } catch (ObjectNotFoundException e) {
                throw new TechnicalException(e);
            } catch (SchemaException e) {
                throw new TechnicalException(e);
            }
        }
    }
}
