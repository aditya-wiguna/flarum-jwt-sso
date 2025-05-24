import app from 'flarum/forum/app';
import { extend } from 'flarum/common/extend';
import HeaderSecondary from 'flarum/forum/components/HeaderSecondary';
import SessionDropdown from 'flarum/forum/components/SessionDropdown';
import LogInModal from 'flarum/forum/components/LogInModal';
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
      return getForumAttribute('baseUrl') || app.forum.attribute('url') || '';
    } catch (e) {
      return '';
    }
  };

  // Initialize the extension functionality
  const initializeSSO = () => {
    const overrideLogin = getForumAttribute('jwt-sso.override_login', false);
    
    // Override login button behavior
    if (overrideLogin) {
      extend(HeaderSecondary.prototype, 'items', function (items) {
        if (app.session.user) return;
        
        // Replace the existing log in button
        items.replace('logIn', 
          Button.component({
            className: 'Button Button--link',
            onclick: () => {
              window.location.href = getBaseUrl() + '/auth/sso/login';
            },
          }, app.translator.trans('core.forum.header.log_in_link'))
        );
      });

      // Disable the login modal
      extend(LogInModal.prototype, 'oncreate', function() {
        this.hide();
        window.location.href = getBaseUrl() + '/auth/sso/login';
      });
    } else {
      // Add SSO login option to existing login modal
      extend(LogInModal.prototype, 'fields', function (items) {
        items.add('sso-login',
          <div className="Form-group">
            <Button 
              className="Button Button--primary Button--block"
              onclick={() => {
                window.location.href = getBaseUrl() + '/auth/sso/login';
              }}
            >
              {app.translator.trans('jwt-sso.forum.login_with_sso')}
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
          errorMessage = app.translator.trans('jwt-sso.forum.error.missing_token');
          break;
        case 'invalid_state':
          errorMessage = app.translator.trans('jwt-sso.forum.error.invalid_state');
          break;
        case 'invalid_token':
          errorMessage = app.translator.trans('jwt-sso.forum.error.invalid_token');
          break;
        default:
          errorMessage = app.translator.trans('jwt-sso.forum.error.generic', { error: ssoError });
      }
      
      app.alerts.show({
        type: 'error',
        content: errorMessage
      });
      
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  };

  // Try to initialize immediately, if it fails, retry with delays
  try {
    if (app.forum && app.forum.data) {
      initializeSSO();
    } else {
      // Retry with increasing delays
      const retryInitialization = (attempt = 1, maxAttempts = 10) => {
        setTimeout(() => {
          if (app.forum && app.forum.data) {
            initializeSSO();
          } else if (attempt < maxAttempts) {
            retryInitialization(attempt + 1, maxAttempts);
          } else {
            console.warn('JWT SSO: Could not initialize - forum data not available');
          }
        }, attempt * 100); // Exponential delay: 100ms, 200ms, 300ms, etc.
      };
      
      retryInitialization();
    }
  } catch (error) {
    console.error('JWT SSO initialization error:', error);
    
    // Fallback initialization with setTimeout
    setTimeout(() => {
      try {
        initializeSSO();
      } catch (fallbackError) {
        console.error('JWT SSO fallback initialization failed:', fallbackError);
      }
    }, 1000);
  }
});