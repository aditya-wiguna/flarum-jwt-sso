/******/ (() => { // webpackBootstrap
/******/ 	// runtime can't be in strict mode because a global variable is assign and maybe created.
/******/ 	var __webpack_modules__ = ({

/***/ "./src/forum/index.js":
/*!****************************!*\
  !*** ./src/forum/index.js ***!
  \****************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var flarum_forum_app__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! flarum/forum/app */ "flarum/forum/app");
/* harmony import */ var flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(flarum_forum_app__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var flarum_common_extend__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! flarum/common/extend */ "flarum/common/extend");
/* harmony import */ var flarum_common_extend__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(flarum_common_extend__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var flarum_forum_components_HeaderSecondary__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! flarum/forum/components/HeaderSecondary */ "flarum/forum/components/HeaderSecondary");
/* harmony import */ var flarum_forum_components_HeaderSecondary__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(flarum_forum_components_HeaderSecondary__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var flarum_forum_components_SessionDropdown__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! flarum/forum/components/SessionDropdown */ "flarum/forum/components/SessionDropdown");
/* harmony import */ var flarum_forum_components_SessionDropdown__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(flarum_forum_components_SessionDropdown__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var flarum_forum_components_LogInModal__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! flarum/forum/components/LogInModal */ "flarum/forum/components/LogInModal");
/* harmony import */ var flarum_forum_components_LogInModal__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(flarum_forum_components_LogInModal__WEBPACK_IMPORTED_MODULE_4__);
/* harmony import */ var flarum_common_components_Button__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! flarum/common/components/Button */ "flarum/common/components/Button");
/* harmony import */ var flarum_common_components_Button__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(flarum_common_components_Button__WEBPACK_IMPORTED_MODULE_5__);






flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().initializers.add('aditya-wiguna-jwt-sso', function () {
  // Function to safely get forum attributes
  var getForumAttribute = function getForumAttribute(key, defaultValue) {
    if (defaultValue === void 0) {
      defaultValue = null;
    }
    try {
      return (flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum) && (flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum).attribute ? flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum.attribute(key) : defaultValue;
    } catch (e) {
      return defaultValue;
    }
  };

  // Function to safely get base URL
  var getBaseUrl = function getBaseUrl() {
    try {
      return getForumAttribute('baseUrl') || flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum.attribute('url') || '';
    } catch (e) {
      return '';
    }
  };

  // Initialize the extension functionality
  var initializeSSO = function initializeSSO() {
    var overrideLogin = getForumAttribute('jwt-sso.overrideLogin', false);

    // Override login button behavior
    if (overrideLogin) {
      (0,flarum_common_extend__WEBPACK_IMPORTED_MODULE_1__.extend)((flarum_forum_components_HeaderSecondary__WEBPACK_IMPORTED_MODULE_2___default().prototype), 'items', function (items) {
        if ((flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().session).user) return;

        // Replace the existing log in button
        items.replace('logIn', flarum_common_components_Button__WEBPACK_IMPORTED_MODULE_5___default().component({
          className: 'Button Button--link',
          onclick: function onclick() {
            window.location.href = getBaseUrl() + '/auth/sso/login';
          }
        }, flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().translator.trans('core.forum.header.log_in_link')));
      });

      // Disable the login modal
      (0,flarum_common_extend__WEBPACK_IMPORTED_MODULE_1__.extend)((flarum_forum_components_LogInModal__WEBPACK_IMPORTED_MODULE_4___default().prototype), 'oncreate', function () {
        this.hide();
        window.location.href = getBaseUrl() + '/auth/sso/login';
      });
    } else {
      // Add SSO login option to existing login modal
      (0,flarum_common_extend__WEBPACK_IMPORTED_MODULE_1__.extend)((flarum_forum_components_LogInModal__WEBPACK_IMPORTED_MODULE_4___default().prototype), 'fields', function (items) {
        items.add('sso-login', m("div", {
          className: "Form-group"
        }, m((flarum_common_components_Button__WEBPACK_IMPORTED_MODULE_5___default()), {
          className: "Button Button--primary Button--block",
          onclick: function onclick() {
            window.location.href = getBaseUrl() + '/auth/sso/login';
          }
        }, flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().translator.trans('jwt-sso.forum.login_with_sso'))), -10);
      });
    }

    // Override logout to use SSO logout
    (0,flarum_common_extend__WEBPACK_IMPORTED_MODULE_1__.extend)((flarum_forum_components_SessionDropdown__WEBPACK_IMPORTED_MODULE_3___default().prototype), 'items', function (items) {
      if (!(flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().session).user) return;
      items.replace('logOut', flarum_common_components_Button__WEBPACK_IMPORTED_MODULE_5___default().component({
        icon: 'fas fa-sign-out-alt',
        onclick: function onclick() {
          fetch(getBaseUrl() + '/auth/sso/logout', {
            method: 'POST',
            headers: {
              'X-CSRF-Token': (flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().session).csrfToken
            }
          }).then(function () {
            window.location.reload();
          });
        }
      }, flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().translator.trans('core.forum.header.log_out_button')));
    });

    // Handle SSO errors
    var urlParams = new URLSearchParams(window.location.search);
    var ssoError = urlParams.get('sso_error');
    if (ssoError) {
      var errorMessage;
      switch (ssoError) {
        case 'missing_token':
          errorMessage = flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().translator.trans('jwt-sso.forum.error.missing_token');
          break;
        case 'invalid_state':
          errorMessage = flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().translator.trans('jwt-sso.forum.error.invalid_state');
          break;
        case 'invalid_token':
          errorMessage = flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().translator.trans('jwt-sso.forum.error.invalid_token');
          break;
        default:
          errorMessage = flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().translator.trans('jwt-sso.forum.error.generic', {
            error: ssoError
          });
      }
      flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().alerts.show({
        type: 'error',
        content: errorMessage
      });

      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  };

  // Try to initialize immediately, if it fails, retry with delays
  try {
    if ((flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum) && (flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum).data) {
      initializeSSO();
    } else {
      // Retry with increasing delays
      var _retryInitialization = function retryInitialization(attempt, maxAttempts) {
        if (attempt === void 0) {
          attempt = 1;
        }
        if (maxAttempts === void 0) {
          maxAttempts = 10;
        }
        setTimeout(function () {
          if ((flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum) && (flarum_forum_app__WEBPACK_IMPORTED_MODULE_0___default().forum).data) {
            initializeSSO();
          } else if (attempt < maxAttempts) {
            _retryInitialization(attempt + 1, maxAttempts);
          } else {
            console.warn('JWT SSO: Could not initialize - forum data not available');
          }
        }, attempt * 100); // Exponential delay: 100ms, 200ms, 300ms, etc.
      };
      _retryInitialization();
    }
  } catch (error) {
    console.error('JWT SSO initialization error:', error);

    // Fallback initialization with setTimeout
    setTimeout(function () {
      try {
        initializeSSO();
      } catch (fallbackError) {
        console.error('JWT SSO fallback initialization failed:', fallbackError);
      }
    }, 1000);
  }
});

/***/ }),

/***/ "flarum/common/components/Button":
/*!*****************************************************************!*\
  !*** external "flarum.core.compat['common/components/Button']" ***!
  \*****************************************************************/
/***/ ((module) => {

"use strict";
module.exports = flarum.core.compat['common/components/Button'];

/***/ }),

/***/ "flarum/common/extend":
/*!******************************************************!*\
  !*** external "flarum.core.compat['common/extend']" ***!
  \******************************************************/
/***/ ((module) => {

"use strict";
module.exports = flarum.core.compat['common/extend'];

/***/ }),

/***/ "flarum/forum/app":
/*!**************************************************!*\
  !*** external "flarum.core.compat['forum/app']" ***!
  \**************************************************/
/***/ ((module) => {

"use strict";
module.exports = flarum.core.compat['forum/app'];

/***/ }),

/***/ "flarum/forum/components/HeaderSecondary":
/*!*************************************************************************!*\
  !*** external "flarum.core.compat['forum/components/HeaderSecondary']" ***!
  \*************************************************************************/
/***/ ((module) => {

"use strict";
module.exports = flarum.core.compat['forum/components/HeaderSecondary'];

/***/ }),

/***/ "flarum/forum/components/LogInModal":
/*!********************************************************************!*\
  !*** external "flarum.core.compat['forum/components/LogInModal']" ***!
  \********************************************************************/
/***/ ((module) => {

"use strict";
module.exports = flarum.core.compat['forum/components/LogInModal'];

/***/ }),

/***/ "flarum/forum/components/SessionDropdown":
/*!*************************************************************************!*\
  !*** external "flarum.core.compat['forum/components/SessionDropdown']" ***!
  \*************************************************************************/
/***/ ((module) => {

"use strict";
module.exports = flarum.core.compat['forum/components/SessionDropdown'];

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be in strict mode.
(() => {
"use strict";
/*!******************!*\
  !*** ./forum.js ***!
  \******************/
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _src_forum__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./src/forum */ "./src/forum/index.js");

})();

module.exports = __webpack_exports__;
/******/ })()
;
//# sourceMappingURL=forum.js.map