package de.sventorben.keycloak.authentication.hidpd;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.List;

import de.sventorben.keycloak.services.messages.Messages;

import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

final class HomeIdpDiscoveryAuthenticator extends AbstractUsernameFormAuthenticator {

    private static final Logger LOG = Logger.getLogger(HomeIdpDiscoveryAuthenticator.class);

    private final AbstractHomeIdpDiscoveryAuthenticatorFactory.DiscovererConfig discovererConfig;

    HomeIdpDiscoveryAuthenticator(AbstractHomeIdpDiscoveryAuthenticatorFactory.DiscovererConfig discovererConfig) {
        this.discovererConfig = discovererConfig;
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        HomeIdpAuthenticationFlowContext context = new HomeIdpAuthenticationFlowContext(authenticationFlowContext);
        if (context.loginPage().shouldByPass()) {
            String usernameHint = usernameHint(authenticationFlowContext, context);
            if (usernameHint != null) {
                String username = setUserInContext(authenticationFlowContext, usernameHint);
                final List<IdentityProviderModel> homeIdps = context.discoverer(discovererConfig).discoverForUser(authenticationFlowContext, username);
                if (!homeIdps.isEmpty()) {
                    context.rememberMe().remember(username);
                    redirectOrChallenge(context, username, homeIdps);
                    return;
                }
            }
        }
        context.authenticationChallenge().forceChallenge();
    }

    private String usernameHint(AuthenticationFlowContext authenticationFlowContext, HomeIdpAuthenticationFlowContext context) {
        String usernameHint = trimToNull(context.loginHint().getFromSession());
        if (usernameHint == null) {
            usernameHint = trimToNull(authenticationFlowContext.getAuthenticationSession().getAuthNote(ATTEMPTED_USERNAME));
        }
        return usernameHint;
    }

    private void redirectOrChallenge(HomeIdpAuthenticationFlowContext context, String username, List<IdentityProviderModel> homeIdps) {
        if (homeIdps.size() == 1 || context.config().forwardToFirstMatch()) {
            IdentityProviderModel homeIdp = homeIdps.get(0);
            context.loginHint().setInAuthSession(homeIdp, username);
            context.redirector().redirectTo(homeIdp);
        } else {
            context.authenticationChallenge().forceChallenge(homeIdps);
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        MultivaluedMap<String, String> formData = authenticationFlowContext.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            LOG.debugf("Login canceled");
            authenticationFlowContext.cancelLogin();
            return;
        }

        HomeIdpAuthenticationFlowContext context = new HomeIdpAuthenticationFlowContext(authenticationFlowContext);

        String tryUsername;
        if (context.reauthentication().required() && authenticationFlowContext.getUser() != null) {
            tryUsername = authenticationFlowContext.getUser().getUsername();
        } else {
            tryUsername = formData.getFirst(AuthenticationManager.FORM_USERNAME);
        }

        String username = setUserInContext(authenticationFlowContext, tryUsername);
        if (username == null) {
            LOG.debugf("No username in request");
            return;
        }


        final List<IdentityProviderModel> homeIdps = context.discoverer(discovererConfig).discoverForUser(authenticationFlowContext, username);
        if (homeIdps.isEmpty()) {
            if (authenticationFlowContext.getUser() != null) {
                authenticationFlowContext.attempted();
                context.loginHint().setInAuthSession(username);
            } else {
                authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
                Response challengeResponse = challenge(authenticationFlowContext, getMessageIfLoginEmailAllowed(authenticationFlowContext, Messages.UNKNOWN_USERNAME), FIELD_USERNAME);
                authenticationFlowContext.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, challengeResponse);
            }
        } else {
            RememberMe rememberMe = context.rememberMe();
            rememberMe.handleAction(formData);
            rememberMe.remember(username);
            redirectOrChallenge(context, username, homeIdps);
        }
    }

    private String setUserInContext(AuthenticationFlowContext context, String username) {
        context.clearUser();

        username = trimToNull(username);

        if (username == null) {
            LOG.warn("No or empty username found in request");
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, getMessageIfLoginEmailAllowed(context, Messages.MISSING_USERNAME), FIELD_USERNAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        }

        LOG.debugf("Found username '%s' in request", username);
        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(ATTEMPTED_USERNAME, username);

        context.setUser(findUserByUsername(context, username));

        return username;
    }

    private UserModel findUserByUsername(AuthenticationFlowContext context, String username) {
        try {
            return KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(),
                username);
        } catch (ModelDuplicateException ex) {
            LOG.warnf(ex, "Could not uniquely identify the user. Multiple users with name or email '%s' found.",
                username);
        }

        return null;
    }

    private static String trimToNull(String username) {
        if (username != null) {
            username = username.trim();
            if ("".equalsIgnoreCase(username))
                username = null;
        }
        return username;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsername();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return context.getRealm().isLoginWithEmailAllowed() ? "invalidUsernameOrEmailMessage" : "invalidUsernameMessage";
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    private String getMessageIfLoginEmailAllowed(AuthenticationFlowContext context, String message) {
        if (context.getRealm().isLoginWithEmailAllowed()) {
            switch (message) {
                case Messages.MISSING_USERNAME:
                    return Messages.MISSING_EMAIL;
                case Messages.UNKNOWN_USERNAME:
                    return Messages.UNKNOWN_EMAIL;
            }
        }
        return message;
    }
}
