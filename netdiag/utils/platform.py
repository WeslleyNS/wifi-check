"""
Utilitários de detecção de plataforma e privilégios.

Usados pelo main.py antes de instanciar qualquer módulo.
Sem dependências de terceiros — apenas built-ins do Python 3.10+.
"""

from __future__ import annotations

import os
import platform
import sys

from netdiag.models import Platform, PlatformInfo, PrivilegeInfo


def detect_platform() -> PlatformInfo:
    """
    Detecta a plataforma de execução atual.

    Returns:
        PlatformInfo com SO, versão e arquitetura.
    """
    system = platform.system().lower()
    arch = platform.machine()

    if system == "windows":
        os_version = f"Windows {platform.release()} {_get_windows_build_label()}".strip()
        return PlatformInfo(
            name=Platform.WINDOWS,
            os_version=os_version,
            architecture=arch,
        )
    elif system == "darwin":
        mac_ver = platform.mac_ver()[0]  # ex: "14.4.1"
        os_version = f"macOS {mac_ver}"
        return PlatformInfo(
            name=Platform.MACOS,
            os_version=os_version,
            architecture=arch,
        )
    else:
        return PlatformInfo(
            name=Platform.UNSUPPORTED,
            os_version=f"{platform.system()} {platform.release()}",
            architecture=arch,
        )


def check_privileges() -> PrivilegeInfo:
    """
    Verifica se o processo está rodando com privilégios elevados.

    Windows: verifica associação ao grupo Administradores via ctypes (built-in).
    macOS  : verifica se o UID efetivo é 0 (root).

    Returns:
        PrivilegeInfo com flag is_elevated e lista de coletas que serão
        ignoradas caso não seja elevado.
    """
    is_elevated = _check_elevated()
    skipped: list[str] = []

    if not is_elevated:
        system = platform.system().lower()
        if system == "windows":
            skipped.append(
                "wevtutil (logs WLAN-AutoConfig — requer Administrador; "
                "execute como Admin para habilitar análise de eventos)"
            )
        elif system == "darwin":
            skipped.append(
                "wdutil info (estado detalhado da interface — requer sudo; "
                "usando system_profiler SPAirPortDataType como fallback)"
            )

    return PrivilegeInfo(is_elevated=is_elevated, skipped_collections=skipped)


def _check_elevated() -> bool:
    """
    Verifica elevação de privilégio de forma multiplataforma.

    Returns:
        True se o processo possui privilégios elevados.
    """
    system = platform.system().lower()
    if system == "windows":
        return _check_elevated_windows()
    else:
        # macOS / Linux
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False


def _check_elevated_windows() -> bool:
    """
    Verifica se o processo Windows é membro do grupo Administradores.

    Usa ctypes (built-in) para chamar IsUserAnAdmin() via Shell32.
    Fallback seguro para False em caso de qualquer exceção.

    Returns:
        True se for Administrador.
    """
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def _get_windows_build_label() -> str:
    """
    Retorna o label de build do Windows (ex: '22H2', '23H2').

    Lê do registro via winreg (built-in do Python no Windows).

    Returns:
        Label de build ou string vazia se não disponível.
    """
    try:
        import winreg  # type: ignore[import]
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )
        display_version, _ = winreg.QueryValueEx(key, "DisplayVersion")
        winreg.CloseKey(key)
        return str(display_version)
    except Exception:  # noqa: BLE001
        return ""
