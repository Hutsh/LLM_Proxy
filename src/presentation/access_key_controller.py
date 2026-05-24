#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""访问密钥管理 API。"""

from __future__ import annotations

from flask import jsonify, request
from flask.typing import ResponseReturnValue

from ..application.app_context import AppContext
from ..services import AccessKeyService, AuthenticationService, SettingsService
from .controller_utils import build_value_error_response, get_json_object
from .decorators import require_authentication


class AccessKeyController:
    """处理数据面访问密钥管理 API。"""

    def __init__(
        self,
        ctx: AppContext,
        access_key_service: AccessKeyService,
        settings_service: SettingsService,
        auth_service: AuthenticationService,
    ):
        self._app = ctx.flask_app
        self._logger = ctx.logger
        self._config_manager = ctx.config_manager
        self._access_key_service = access_key_service
        self._settings_service = settings_service
        self._auth_service = auth_service
        self._register_routes()

    def _register_routes(self) -> None:
        auth = require_authentication(self._auth_service)

        self._app.route("/api/access-keys", methods=["GET"])(auth(self.list_access_keys))
        self._app.route("/api/access-keys", methods=["POST"])(auth(self.create_access_key))
        self._app.route("/api/access-keys/settings", methods=["PUT"])(auth(self.update_settings))
        self._app.route("/api/access-keys/<int:key_id>", methods=["GET"])(auth(self.get_access_key))
        self._app.route("/api/access-keys/<int:key_id>", methods=["PUT"])(auth(self.update_access_key))
        self._app.route("/api/access-keys/<int:key_id>", methods=["DELETE"])(auth(self.delete_access_key))
        self._app.route("/api/access-keys/<int:key_id>/toggle", methods=["POST"])(auth(self.toggle_access_key))

    def list_access_keys(self) -> ResponseReturnValue:
        try:
            return jsonify(
                {
                    "enabled": self._config_manager.is_chat_api_key_enabled(),
                    "access_keys": self._access_key_service.list_access_keys(),
                    "available_models": self._access_key_service.get_available_models(),
                }
            )
        except Exception as exc:
            self._logger.error("Error listing access keys: %s", exc)
            return jsonify({"error": str(exc)}), 500

    def get_access_key(self, key_id: int) -> ResponseReturnValue:
        try:
            access_key = self._access_key_service.get_access_key(key_id)
            if not access_key:
                return jsonify({"error": "Access key not found"}), 404
            return jsonify(access_key)
        except Exception as exc:
            self._logger.error("Error getting access key: %s", exc)
            return jsonify({"error": str(exc)}), 500

    def create_access_key(self) -> ResponseReturnValue:
        try:
            payload = get_json_object()
            access_key = self._access_key_service.create_access_key(
                payload.get("name"),
                api_key=payload.get("api_key"),
                model_permissions=payload.get("model_permissions"),
            )
            self._logger.info("Access key created: id=%s", access_key.get("id"))
            return jsonify(access_key), 201
        except ValueError as exc:
            return build_value_error_response(exc)
        except Exception as exc:
            self._logger.error("Error creating access key: %s", exc)
            return jsonify({"error": str(exc)}), 500

    def update_access_key(self, key_id: int) -> ResponseReturnValue:
        try:
            payload = get_json_object()
            updated = self._access_key_service.update_access_key(
                key_id,
                name=payload.get("name"),
                access_enabled=payload.get("access_enabled"),
                model_permissions_provided="model_permissions" in payload,
                model_permissions=payload.get("model_permissions"),
            )
            if not updated:
                return jsonify({"error": "Access key not found or no changes provided"}), 404
            self._logger.info("Access key updated: id=%s", key_id)
            return jsonify({"message": "Access key updated successfully"})
        except ValueError as exc:
            return build_value_error_response(exc)
        except Exception as exc:
            self._logger.error("Error updating access key: %s", exc)
            return jsonify({"error": str(exc)}), 500

    def toggle_access_key(self, key_id: int) -> ResponseReturnValue:
        try:
            if not self._access_key_service.toggle_access_key(key_id):
                return jsonify({"error": "Access key not found"}), 404
            self._logger.info("Access key toggled: id=%s", key_id)
            return jsonify({"message": "Access key status toggled successfully"})
        except Exception as exc:
            self._logger.error("Error toggling access key: %s", exc)
            return jsonify({"error": str(exc)}), 500

    def delete_access_key(self, key_id: int) -> ResponseReturnValue:
        try:
            if not self._access_key_service.delete_access_key(key_id):
                return jsonify({"error": "Access key not found"}), 404
            self._logger.info("Access key deleted: id=%s", key_id)
            return jsonify({"message": "Access key deleted successfully"})
        except Exception as exc:
            self._logger.error("Error deleting access key: %s", exc)
            return jsonify({"error": str(exc)}), 500

    def update_settings(self) -> ResponseReturnValue:
        try:
            payload = get_json_object()
            enabled = self._settings_service.update_chat_api_key_enabled(payload.get("enabled"))
            self._logger.info("Chat API key auth updated: enabled=%s", enabled)
            return jsonify({"enabled": enabled})
        except ValueError as exc:
            return build_value_error_response(exc)
        except Exception as exc:
            self._logger.error("Error updating API key auth settings: %s", exc)
            return jsonify({"error": str(exc)}), 500
