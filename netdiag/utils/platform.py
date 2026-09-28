"""
Utilitários de detecção de plataforma, privilégios e diretório de saída.

Usados pelo main.py antes de instanciar qualquer módulo.
Sem dependências de terceiros — apenas built-ins do Python 3.10+.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

from netdiag.models import Platform, PlatformInfo, PrivilegeInfo

# Nome da pasta criada no Desktop para todos os arquivos do NetDiag
NETDIAG_FOLDER_NAME = "NetDiag-Logs"


# ---------------------------------------------------------------------------
# Detecção de plataforma
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Verificação de privilégios
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Diretório de saída centralizado
# ---------------------------------------------------------------------------

def get_netdiag_logs_dir() -> Path:
    """
    Retorna e cria a pasta ``Desktop/NetDiag-Logs/`` para todos os arquivos.

    Todo o conteúdo gerado pelo NetDiag (HTML, TXT, ZIP, JSONL) é salvo aqui,
    permitindo compactar a pasta e enviar para análise sem precisar procurar
    arquivos espalhados.

    Resolução do Desktop (em ordem):
    1. winreg  «User Shell Folders\\Desktop» (funciona com OneDrive corporativo).
    2. ``%USERPROFILE%\\Desktop``
    3. Variáveis de ambiente OneDrive + Desktop
    4. ``~/Desktop``  (macOS / Linux)
    5. ``~/`` (fallback universal)

    Returns:
        Path da pasta ``NetDiag-Logs`` já criada no disco.
    """
    desktop = _resolve_desktop()
    logs_dir = desktop / NETDIAG_FOLDER_NAME
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def _resolve_desktop() -> Path:
    """
    Detecta o caminho real do Desktop de forma multiplataforma.

    Returns:
        Path do Desktop do usuário atual.
    """
    system = platform.system().lower()
    if system == "windows":
        return _get_windows_desktop()
    desktop = Path.home() / "Desktop"
    return desktop if desktop.exists() else Path.home()


def _get_windows_desktop() -> Path:
    """
    Obtém o caminho do Desktop no Windows, incluindo ambientes OneDrive.

    Estratégia (em ordem de prioridade):
    1. winreg — «User Shell Folders\\Desktop» (fonte oficial do Windows).
    2. ``%USERPROFILE%\\Desktop``
    3. OneDriveConsumer / OneDriveCommercial / OneDrive + Desktop
    4. ``Path.home()``

    Returns:
        Path do Desktop do Windows.
    """
    # 1. Registro do Windows (suporta OneDrive corporativo)
    try:
        import winreg  # type: ignore[import]
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        )
        desktop_raw, _ = winreg.QueryValueEx(key, "Desktop")
        winreg.CloseKey(key)
        import ctypes
        buf = ctypes.create_unicode_buffer(32767)
        ctypes.windll.kernel32.ExpandEnvironmentStringsW(  # type: ignore[attr-defined]
            str(desktop_raw), buf, 32767
        )
        desktop = Path(buf.value)
        if desktop.exists():
            return desktop
    except Exception:  # noqa: BLE001
        pass

    # 2. USERPROFILE\Desktop
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        desktop = Path(user_profile) / "Desktop"
        if desktop.exists():
            return desktop

    # 3. OneDrive + Desktop
    for env_var in ("OneDriveConsumer", "OneDriveCommercial", "OneDrive"):
        onedrive = os.environ.get(env_var, "")
        if onedrive:
            for desktop_name in ("Desktop", "Área de Trabalho"):
                desktop = Path(onedrive) / desktop_name
                if desktop.exists():
                    return desktop

    # 4. Fallback
    return Path.home()


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _check_elevated() -> bool:
    """
    Verifica elevação de privilégio de forma multiplataforma.

    Returns:
        True se o processo possui privilégios elevados.
    """
    system = platform.system().lower()
    if system == "windows":
        return _check_elevated_windows()
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
