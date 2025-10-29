# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['bsot.py'],
    pathex=[],
    binaries=[],
    datas=[('commands/utils/log_analyzer.py', 'commands/utils')],
    hiddenimports=[
        'commands.file',
        'commands.network',
        'commands.data',
        'commands.auth',
        'commands.system',
        'commands.logs',
        'commands.data_commands',
        'commands.data_commands.url_decode',
        'commands.data_commands.base64_decode',
        'commands.data_commands.hex_decode',
        'commands.data_commands.email_header',
        'commands.utils.log_analyzer',
        'click',
        'requests',
        'dns.resolver',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='bsot',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
