"""
This initialize plugin for authorization using framework OAuth 2.0
for application OctoPrint
"""
import logging
from octoprint import plugin
from octoprint_oauth2.oauth_user_manager import OAuthBasedUserManager


class OAuth2Plugin(plugin.StartupPlugin, plugin.TemplatePlugin,
                   plugin.SettingsPlugin, plugin.AssetPlugin):
    """
    Class for OAuth2 plugin for application OctoPrint
    """

    # Template plugin mixin
    def get_template_configs(self):
        """
        Plugin sets used templates
        """
        self._logger.info("OAuth 2.0 get template configs")
        return [{"type": "navbar", "template": "oauth2_login.jinja2",
                 "custom_bindings": False, "replaces": "login"}]

    # Asset plugin mixin
    def get_assets(self):
        """
        Plugin sets assets
        """
        self._logger.info("OAuth 2.0 get assets")
        return {"js": ["js/oauth2.js"]}

    def get_settings_restricted_paths(self):
        """
        Plugin set restricted paths of config.yaml
        """
        return {"admin": [["plugins", "oauth2"]]}


def user_factory_hook(components, settings, *args, **kwargs):
    """
    User factory hook, to initialize OAuthBasedUserManager, which controls login users
    """
    logging.getLogger("octoprint.plugins." + __name__).info(
        "OAuth 2.0 hooking OAuthBasedUserManager")
    return OAuthBasedUserManager(components, settings)


__plugin_name__ = "OAuth"
__plugin_implementation__ = OAuth2Plugin()
__plugin_hooks__ = {
    "octoprint.users.factory": user_factory_hook
}
