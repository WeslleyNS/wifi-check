# -*- mode: python ; coding: utf-8 -*-
# netdiag-windows.spec — PyInstaller spec para geração do netdiag.exe (Windows)
#
# Uso:
#   pyinstaller netdiag-windows.spec
#
# Resultado: dist/netdiag.exe (binário único, sem necessidade de Python instalado)
# Modo básico não requer privilégios de Administrador.

block_cipher = None

a = Analysis(
    ['run.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'netdiag.modules.passive_collector',
        'netdiag.modules.synthetic_tester',
        'netdiag.modules.decision_engine',
        'netdiag.output.report_generator',
        'netdiag.output.jsonl_writer',
        'netdiag.utils.platform',
        'xml.etree.ElementTree',
        'ctypes',
        'winreg',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Excluir módulos pesados não utilizados
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'scipy',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='netdiag',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # UPX comprime o executável (opcional, instalar upx separado)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # app de console (não windowed)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,   # None = arquitetura nativa da máquina de build
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/netdiag.ico',  # descomentar quando ícone estiver disponível
)
