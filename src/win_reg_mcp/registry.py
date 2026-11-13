"""Privileged, read/write access to Windows Registry hives and WOW64 views."""

from __future__ import annotations

import base64
import ctypes
import logging
import sys
from collections.abc import Iterator
from typing import Any

from win_reg_mcp.models import RegistryAction, RegistryValue

LOGGER = logging.getLogger(__name__)

HIVE_NAMES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}

REG_TYPE_NAMES = {
    "REG_NONE": "REG_NONE",
    "REG_SZ": "REG_SZ",
    "REG_EXPAND_SZ": "REG_EXPAND_SZ",
    "REG_BINARY": "REG_BINARY",
    "REG_DWORD": "REG_DWORD",
    "REG_DWORD_BIG_ENDIAN": "REG_DWORD_BIG_ENDIAN",
    "REG_LINK": "REG_LINK",
    "REG_MULTI_SZ": "REG_MULTI_SZ",
    "REG_RESOURCE_LIST": "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTOR": "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST": "REG_RESOURCE_REQUIREMENTS_LIST",
    "REG_QWORD": "REG_QWORD",
}


class RegistryError(RuntimeError):
    """Raised when the requested Registry operation cannot be completed."""


def require_windows_admin() -> None:
    """Fail closed unless the process is running elevated on Windows."""
    if sys.platform != "win32":
        raise RuntimeError("win-reg-mcp requires Windows and an elevated administrator process")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError(
            "win-reg-mcp must be launched from an Administrator PowerShell or terminal"
        )


def _winreg_module() -> Any:
    """Load the Windows-only registry module lazily so unit tests run on other platforms."""
    if sys.platform != "win32":
        raise RegistryError("Windows Registry access is only available on Windows")
    import winreg

    return winreg


def _json_safe(value: Any) -> Any:
    """Preserve Registry data types while making binary content serializable."""
    if isinstance(value, bytes):
        return {"__bytes_base64__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


def _from_json_safe(value: Any) -> Any:
    """Restore binary Registry payloads after they have been read from SQLite."""
    if isinstance(value, dict) and set(value) == {"__bytes_base64__"}:
        return base64.b64decode(value["__bytes_base64__"])
    if isinstance(value, list):
        return [_from_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _from_json_safe(item) for key, item in value.items()}
    return value


def _type_name(winreg: Any, raw_type: int) -> str:
    """Translate numeric winreg types into durable names stored in SQLite."""
    for name, value in REG_TYPE_NAMES.items():
        if getattr(winreg, name, object()) == raw_type:
            return name
    return f"REG_TYPE_{raw_type}"


class WindowsRegistry:
    """Enumerate, inspect, and mutate all standard Registry hives and views."""

    def __init__(self, hives: tuple[str, ...], views: tuple[str, ...]) -> None:
        self.hives = hives
        self.views = views
        self.scan_errors = 0

    def _hive_handle(self, hive_name: str) -> Any:
        """Map the stable hive abbreviation to the platform-specific root handle."""
        winreg = _winreg_module()
        attributes = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
            "HKCC": winreg.HKEY_CURRENT_CONFIG,
        }
        try:
            return attributes[hive_name.upper()]
        except KeyError as exc:
            raise RegistryError(f"Unsupported Registry hive: {hive_name}") from exc

    @staticmethod
    def _view_flag(winreg: Any, view: str) -> int:
        """Select a Registry bitness view without silently mixing the two namespaces."""
        flags = {
            "32": winreg.KEY_WOW64_32KEY,
            "64": winreg.KEY_WOW64_64KEY,
            "default": 0,
        }
        try:
            return flags[view.lower()]
        except KeyError as exc:
            raise RegistryError(f"Unsupported Registry view: {view}") from exc

    def iter_values(self) -> Iterator[RegistryValue]:
        """Yield all readable values using iterative depth-first traversal."""
        winreg = _winreg_module()
        self.scan_errors = 0
        for hive_name in self.hives:
            for view in self.views:
                root = self._hive_handle(hive_name)
                view_flag = self._view_flag(winreg, view)
                stack = [""]
                while stack:
                    key_path = stack.pop()
                    try:
                        with winreg.OpenKey(
                            root,
                            key_path,
                            0,
                            winreg.KEY_READ | view_flag,
                        ) as key:
                            values: list[tuple[str, Any, int]] = []
                            subkeys: list[str] = []
                            value_index = 0
                            while True:
                                try:
                                    values.append(winreg.EnumValue(key, value_index))
                                    value_index += 1
                                except OSError as exc:
                                    if getattr(exc, "winerror", None) != 259:
                                        self.scan_errors += 1
                                    break
                            subkey_index = 0
                            while True:
                                try:
                                    subkeys.append(winreg.EnumKey(key, subkey_index))
                                    subkey_index += 1
                                except OSError as exc:
                                    if getattr(exc, "winerror", None) != 259:
                                        self.scan_errors += 1
                                    break
                    except OSError as exc:
                        self.scan_errors += 1
                        if getattr(exc, "winerror", None) not in (2, 3, 5, 6, 87):
                            LOGGER.debug(
                                "Registry key skipped: %s\\%s (%s)",
                                hive_name,
                                key_path,
                                exc,
                            )
                        continue
                    for value_name, value_data, raw_type in values:
                        yield RegistryValue(
                            hive=hive_name,
                            view=view,
                            key_path=key_path,
                            value_name=value_name,
                            value_type=_type_name(winreg, raw_type),
                            value_data=_json_safe(value_data),
                        )
                    for subkey in reversed(subkeys):
                        stack.append(f"{key_path}\\{subkey}" if key_path else subkey)

    def read_value(self, hive: str, view: str, key_path: str, value_name: str) -> dict[str, Any]:
        """Read one exact value so Rollout can build a lossless pre-change backup."""
        winreg = _winreg_module()
        root = self._hive_handle(hive)
        access = winreg.KEY_READ | self._view_flag(winreg, view)
        try:
            with winreg.OpenKey(root, key_path, 0, access) as key:
                data, raw_type = winreg.QueryValueEx(key, value_name)
        except FileNotFoundError:
            return {"exists": False}
        except OSError as exc:
            raise RegistryError(f"Cannot read {hive}\\{key_path}\\{value_name}: {exc}") from exc
        return {
            "exists": True,
            "value_type": _type_name(winreg, raw_type),
            "value_data": _json_safe(data),
        }

    def apply_action(self, action: RegistryAction) -> None:
        """Apply one validated value change without exposing arbitrary registry handles."""
        winreg = _winreg_module()
        root = self._hive_handle(action.hive)
        view_flag = self._view_flag(winreg, action.view)
        if action.action == "set_value":
            if not action.value_type:
                raise RegistryError("set_value requires value_type")
            registry_type = getattr(winreg, action.value_type, None)
            if registry_type is None or not action.value_type.startswith("REG_"):
                raise RegistryError(f"Unsupported Registry data type: {action.value_type}")
            data = _from_json_safe(action.value_data)
            try:
                with winreg.OpenKey(
                    root,
                    action.key_path,
                    0,
                    winreg.KEY_SET_VALUE | view_flag,
                ) as key:
                    winreg.SetValueEx(key, action.value_name, 0, registry_type, data)
                if (
                    action.hive == "HKCU"
                    and action.key_path.casefold() == "control panel\\desktop"
                    and action.value_name.casefold() == "wallpaper"
                    and isinstance(data, str)
                ):
                    self._broadcast_wallpaper_change(data)
            except OSError as exc:
                raise RegistryError(
                    f"Cannot set {action.hive}\\{action.key_path}\\{action.value_name}: {exc}"
                ) from exc
            return
        if action.action == "delete_value":
            try:
                with winreg.OpenKey(
                    root,
                    action.key_path,
                    0,
                    winreg.KEY_SET_VALUE | view_flag,
                ) as key:
                    winreg.DeleteValue(key, action.value_name)
            except OSError as exc:
                raise RegistryError(
                    f"Cannot delete {action.hive}\\{action.key_path}\\{action.value_name}: {exc}"
                ) from exc
            return
        raise RegistryError(f"Unsupported rollout action: {action.action}")

    @staticmethod
    def _broadcast_wallpaper_change(path: str) -> None:
        """Notify the Windows shell when a Registry rollout changes the desktop wallpaper."""
        result = ctypes.windll.user32.SystemParametersInfoW(20, 0, ctypes.c_wchar_p(path), 0x01 | 0x02)
        if not result:
            LOGGER.warning(
                "Wallpaper Registry value was written, but Windows did not accept the update "
                "broadcast for %s",
                path,
            )

    def restore_value(
        self,
        hive: str,
        view: str,
        key_path: str,
        value_name: str,
        snapshot: dict[str, Any],
    ) -> None:
        """Restore a previous value snapshot or remove a value created by Rollout."""
        if not snapshot.get("exists"):
            action = RegistryAction(
                action="delete_value",
                hive=hive,
                view=view,
                key_path=key_path,
                value_name=value_name,
            )
            try:
                self.apply_action(action)
            except RegistryError as exc:
                if "cannot delete" not in str(exc).lower() and "cannot open" not in str(exc).lower():
                    raise
            return
        action = RegistryAction(
            action="set_value",
            hive=hive,
            view=view,
            key_path=key_path,
            value_name=value_name,
            value_type=str(snapshot["value_type"]),
            value_data=snapshot["value_data"],
        )
        self.apply_action(action)

    def key_exists(self, hive: str, view: str, key_path: str) -> bool:
        """Confirm that an LLM-proposed key is real before permitting a mutation."""
        winreg = _winreg_module()
        try:
            with winreg.OpenKey(
                self._hive_handle(hive),
                key_path,
                0,
                winreg.KEY_READ | self._view_flag(winreg, view),
            ):
                return True
        except OSError:
            return False


def normalize_registry_data(value: Any) -> Any:
    """Expose safe Registry data in natural-language prompts and result summaries."""
    if isinstance(value, dict) and "__bytes_base64__" in value:
        raw = base64.b64decode(value["__bytes_base64__"])
        return f"base64:{base64.b64encode(raw).decode('ascii')}"
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        return value
    return value
