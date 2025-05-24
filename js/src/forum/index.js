import app from 'flarum/forum/app';
import { extend, override } from 'flarum/common/extend';
import HeaderSecondary from 'flarum/forum/components/HeaderSecondary';
import SessionDropdown from 'flarum/forum/components/SessionDropdown';
import LogInModal from 'flarum/forum/components/LogInModal';
import SignUpModal from 'flarum/forum/components/SignUpModal';
import Button from 'flarum/common/components/Button';

app.initializers.add('aditya-wiguna-jwt-sso', () => {
  // Function to safely get forum attributes
  const getForumAttribute = (key, defaultValue = null) => {
    try {
      return app.forum && app.forum.attribute ? app.forum.attribute(key) : defaultValue;
    } catch (e) {
      return defaultValue;
    }
  };

  // Function to safely get base URL
  const getBaseUrl = () => {
    try {
      return getForumAttribute('baseUrl') || getForumAttribute('url') || '';
    } catch (e) {
      return '';
    }
  };

  // Initialize the extension functionality
  const initializeSSO = () => {
    const overrideLogin = getForumAttribute('jwt-sso.overrideLogin', false);
    const loginUrl = getBaseUrl() + '/auth/sso/login';
    
    // Override login button behavior
    if (overrideLogin) {
      // Completely override the LogInModal to prevent it from showing
      override(LogInModal.prototype, 'oninit', function(original) {
        // Immediately redirect without showing the modal
        window.location.href = loginUrl;
        return;
      });

      // Also override SignUpModal
      override(SignUpModal.prototype, 'oninit', function(original) {
        window.location.href = loginUrl;
        return;
      });

      // Override the modal show method to intercept login/signup modals
      const originalShow = app.modal.show;
      app.modal.show = (componentClass, ...args) => {
        if (componentClass === LogInModal || componentClass === SignUpModal) {
          window.location.href = loginUrl;
          return;
        }
        return originalShow.call(app.modal, componentClass, ...args);
      };

      // Replace login button in header to redirect directly
      extend(HeaderSecondary.prototype, 'items', function (items) {
        if (app.session.user) return;
        
        // Replace the existing log in button
        if (items.has('logIn')) {
          items.replace('logIn', 
            Button.component({
              className: 'Button Button--link',
              onclick: (e) => {
                e.preventDefault();
                e.stopPropagation();
                window.location.href = loginUrl;
                return false;
              },
            }, app.translator.trans('core.forum.header.log_in_link'))
          );
        }

        // Remove sign up button if it exists
        if (items.has('signUp')) {
          items.remove('signUp');
        }
      });

      // Override SessionDropdown login items for guest users
      extend(SessionDropdown.prototype, 'items', function(items) {
        if (app.session.user) return;

        if (items.has('logIn')) {
          items.replace('logIn',
            Button.component({
              className: 'Button Button--link',
              onclick: (e) => {
                e.preventDefault();
                e.stopPropagation();
                window.location.href = loginUrl;
                return false;
              }
            }, app.translator.trans('core.forum.header.log_in_link'))
          );
        }

        if (items.has('signUp')) {
          items.remove('signUp');
        }
      });

      // Override register route
      app.routes.register = () => {
        window.location.href = loginUrl;
      };

    } else {
      // Add SSO login option to existing login modal when override is disabled
      extend(LogInModal.prototype, 'fields', function (items) {
        items.add('sso-login',
          <div className="Form-group">
            <Button 
              className="Button Button--primary Button--block"
              onclick={() => {
                window.location.href = loginUrl;
              }}
            >
              {app.translator.trans('jwt-sso.forum.login_with_sso', {}, 'Login with SSO')}
            </Button>
          </div>,
          -10
        );
      });
    }

    // Override logout to use SSO logout
    extend(SessionDropdown.prototype, 'items', function (items) {
      if (!app.session.user) return;
      
      items.replace('logOut',
        Button.component({
          icon: 'fas fa-sign-out-alt',
          onclick: () => {
            fetch(getBaseUrl() + '/auth/sso/logout', {
              method: 'POST',
              headers: {
                'X-CSRF-Token': app.session.csrfToken,
              },
            }).then(() => {
              window.location.reload();
            }).catch(() => {
              // Fallback to standard logout
              app.session.logout();
            });
          },
        }, app.translator.trans('core.forum.header.log_out_button'))
      );
    });

    // Handle SSO errors
    const urlParams = new URLSearchParams(window.location.search);
    const ssoError = urlParams.get('sso_error');
    
    if (ssoError) {
      let errorMessage;
      switch (ssoError) {
        case 'missing_token':
          errorMessage = app.translator.trans('jwt-sso.forum.error.missing_token', {}, 'Missing authentication token');
          break;
        case 'invalid_state':
          errorMessage = app.translator.trans('jwt-sso.forum.error.invalid_state', {}, 'Invalid authentication state');
          break;
        case 'invalid_token':
          errorMessage = app.translator.trans('jwt-sso.forum.error.invalid_token', {}, 'Invalid authentication token');
          break;
        case 'authentication_failed':
          errorMessage = app.translator.trans('jwt-sso.forum.error.authentication_failed', {}, 'Authentication failed');
          break;
        default:
          errorMessage = app.translator.trans('jwt-sso.forum.error.generic', { error: ssoError }, `Authentication error: ${ssoError}`);
      }
      
      app.alerts.show({
        type: 'error',
        content: errorMessage
      });
      
      // Clean up URL
      if (window.history && window.history.replaceState) {
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    }
  };

  // Wait for forum data to be available with better error handling
  const waitForForum = (attempt = 1, maxAttempts = 50) => {
    if (app.forum && (app.forum.data || app.forum.attribute)) {
      try {
        initializeSSO();
      } catch (error) {
        console.error('JWT SSO initialization error:', error);
      }
    } else if (attempt < maxAttempts) {
      setTimeout(() => waitForForum(attempt + 1, maxAttempts), 100);
    } else {
      console.warn('JWT SSO: Could not initialize - forum data not available after', maxAttempts, 'attempts');
      // Try to initialize anyway as a fallback
      try {
        initializeSSO();
      } catch (error) {
        console.error('JWT SSO fallback initialization failed:', error);
      }
    }
  };

  // Start waiting for forum data
  waitForForum();
});