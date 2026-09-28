# -*- mode: python ; coding: utf-8 -*-
# netdiag-macos.spec — PyInstaller spec para geração do binário netdiag (macOS)
#
# Uso:
#   pyinstaller netdiag-macos.spec
#
# Resultado: dist/netdiag (binário unix único)
#
# AVISO GATEKEEPER (documentar no README):
#   O binário não é assinado por padrão (requer Apple Developer ID pago).
#   Usuários macOS precisarão remover a quarentena antes do primeiro uso:
#     xattr -d com.apple.quarantine ./netdiag
#   Ou: Finder → clique direito → Abrir → Abrir mesmo assim.

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
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'scipy',
        'winreg',   # módulo Windows, excluir explicitamente no build macOS
        'ctypes.wintypes',
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
    strip=True,         # strip de símbolos de debug reduz tamanho no macOS
    upx=False,          # UPX pode causar problemas com Gatekeeper no macOS
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,   # None = nativo; para universal2: 'universal2'
    codesign_identity=None,     # definir se tiver Apple Developer ID
    entitlements_file=None,
    # icon='assets/netdiag.icns',  # descomentar quando ícone estiver disponível
)
