package de.sventorben.keycloak.authentication.hidpd;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class SingleSignOnTest {

    private static final String USER_ID = "user-id";

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    AuthenticationFlowContext context;

    @Mock
    UserModel user;

    @InjectMocks
    SingleSignOn cut;

    @Test
    @DisplayName("Given a user and an SSO auth note for that user, then SSO is established")
    void givenUserAndSsoAuthNoteThenEstablished() {
        given(user.getId()).willReturn(USER_ID);
        given(context.getUser()).willReturn(user);
        given(context.getAuthenticationSession().getAuthenticatedUser()).willReturn(user);
        given(context.getAuthenticationSession().getAuthNote(AuthenticationManager.SSO_AUTH))
            .willReturn(USER_ID);

        assertThat(cut.established()).isTrue();
    }

    @Test
    @DisplayName("Given an SSO auth note for a different user, then the flow fails with a user conflict")
    void givenSsoAuthNoteForDifferentUserThenUserConflict() {
        // Since Keycloak 26.8.2 the note is bound to the user the cookie authenticated
        // (CVE-2026-112208). Completing SSO for whoever is in the context now would let a stale note
        // sign in another user, so the conflict must surface instead of returning true or false.
        given(user.getId()).willReturn(USER_ID);
        given(context.getUser()).willReturn(user);
        given(context.getAuthenticationSession().getAuthenticatedUser()).willReturn(user);
        given(context.getAuthenticationSession().getAuthNote(AuthenticationManager.SSO_AUTH))
            .willReturn("another-user-id");

        assertThatThrownBy(() -> cut.established())
            .isInstanceOf(AuthenticationFlowException.class)
            .extracting(e -> ((AuthenticationFlowException) e).getError())
            .isEqualTo(AuthenticationFlowError.USER_CONFLICT);
    }

    @Test
    @DisplayName("Given no user, then SSO is not established")
    void givenNoUserThenNotEstablished() {
        given(context.getUser()).willReturn(null);

        assertThat(cut.established()).isFalse();
    }

    @Test
    @DisplayName("Given a user but no SSO auth note, then SSO is not established")
    void givenNoSsoAuthNoteThenNotEstablished() {
        // Forced re-authentication, step-up and forked flows all leave the note unset, so the user
        // must still be challenged.
        given(context.getUser()).willReturn(user);
        given(context.getAuthenticationSession().getAuthNote(AuthenticationManager.SSO_AUTH))
            .willReturn(null);

        assertThat(cut.established()).isFalse();
    }
}
