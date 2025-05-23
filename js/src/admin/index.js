import app from 'flarum/admin/app';

app.initializers.add('aditya-wiguna-jwt-sso', () => {
  app.extensionData
    .for('aditya-wiguna-jwt-sso')
    .registerSetting({
      setting: 'jwt-sso.main_site_url',
      type: 'url',
      label: app.translator.trans('jwt-sso.admin.main_site_url_label'),
      help: app.translator.trans('jwt-sso.admin.main_site_url_help'),
    })
    .registerSetting({
      setting: 'jwt-sso.login_url',
      type: 'url',
      label: app.translator.trans('jwt-sso.admin.login_url_label'),
      help: app.translator.trans('jwt-sso.admin.login_url_help'),
    })
    .registerSetting({
      setting: 'jwt-sso.logout_url',
      type: 'url',
      label: app.translator.trans('jwt-sso.admin.logout_url_label'),
      help: app.translator.trans('jwt-sso.admin.logout_url_help'),
    })
    .registerSetting({
      setting: 'jwt-sso.secret_key',
      type: 'password',
      label: app.translator.trans('jwt-sso.admin.secret_key_label'),
      help: app.translator.trans('jwt-sso.admin.secret_key_help'),
    })
    .registerSetting({
      setting: 'jwt-sso.issuer',
      type: 'text',
      label: app.translator.trans('jwt-sso.admin.issuer_label'),
      help: app.translator.trans('jwt-sso.admin.issuer_help'),
    })
    .registerSetting({
      setting: 'jwt-sso.default_groups',
      type: 'text',
      label: app.translator.trans('jwt-sso.admin.default_groups_label'),
      help: app.translator.trans('jwt-sso.admin.default_groups_help'),
    })
    .registerSetting({
      setting: 'jwt-sso.override_login',
      type: 'boolean',
      label: app.translator.trans('jwt-sso.admin.override_login_label'),
      help: app.translator.trans('jwt-sso.admin.override_login_help'),
    });
});