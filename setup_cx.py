"""cx_Freeze setup for BSOT - faster startup than PyInstaller"""

from cx_Freeze import setup, Executable

build_options = {
    "packages": [
        "bsot",
        "bsot.phishing",
        "bsot.intel", 
        "bsot.file",
        "bsot.network",
        "bsot.logs",
        "bsot.data",
        "bsot.auth",
        "bsot.system",
        "bsot.ir",
        "bsot.malware",
        "bsot.report",
        "bsot.osint",
        "click",
        "requests",
    ],
    "excludes": [
        "tkinter",
        "unittest",
        "test",
        "distutils",
    ],
    "include_files": [],
    "optimize": 2,
}

setup(
    name="bsot",
    version="2.1.0",
    description="Blue Security Operations Toolkit",
    options={"build_exe": build_options},
    executables=[
        Executable(
            "bsot.py",
            target_name="bsot",
        )
    ],
)

