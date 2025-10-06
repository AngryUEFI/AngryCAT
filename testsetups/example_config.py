"""
Global configuration for AngryCAT test setups.

This file contains global configuration values like API URLs and tokens
that can be used across all test setups.
"""

config = {
    # URL and token to login into HA instance to control test setup power, optional
    "ha_base_url": "https://api.angrycat.example.com",
    "ha_token": "your-api-token-here",
    "log_level": "WARNING",
    # will automatically disable itself it output is not a tty
    "use_colors": True,
}
