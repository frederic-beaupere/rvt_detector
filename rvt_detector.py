"""
Simple helper to:
 - detect *.rvt info like version or workshare status.
 - detect installed Autodesk Revit versions. (windows only)
"""

import winreg
import sys
import re
import string
import olefile

__version__ = "0.2.0"


def get_basic_info(rvt_file):
    """
    Searches and returns the BasicFileInfo stream in the rvt file ole structure.
    :param rvt_file: model file path
    :return:str: BasicFileInfo
    """
    if olefile.isOleFile(rvt_file):
        rvt_ole = olefile.OleFileIO(rvt_file)
        basic_info = rvt_ole.openstream("BasicFileInfo").read().decode("utf-16le", "ignore")
        return basic_info
    else:
        print("file does not appear to be an ole file: {}".format(rvt_file))


def get_rvt_file_version(rvt_file):
    """
    Finds rvt version in BasicFileInfo stream of rvt file ole structure.
    :param rvt_file: model file path
    :return:str: rvt_file_version
    """
    file_info = get_basic_info(rvt_file)
    pattern = re.compile(r" \d{4} ")
    rvt_file_version = re.search(pattern, file_info)[0].strip()
    return rvt_file_version


def get_rvt_info(rvt_file):
    """
    Finds rvt file info in BasicFileInfo stream of rvt file ole structure:
    Worksharing
    Central Model Path, Revit Build, Last Save Path, Local Changes Saved To Central
    Central model's version number, Unique Document GUID, Unique Document Increments
    :param rvt_file: model file path
    :return:dict: rvt_file information found
    """
    rvt_info = {}
    file_info = get_basic_info(rvt_file)

    for line in file_info.split("\r\n"):
        line = bytes(line, 'utf-8').decode('utf-8', 'ignore')
        if "Worksharing:" in line:
            if "Worksharing: Not enabled" in line:
                rvt_info["rvt_file_ws"] = False
            else:
                rvt_info["rvt_file_ws"] = True
        elif "Central Model Path:" in line:
            rvt_info["CentralModelPath"] = line.split()[-1]
        elif "Revit Build:" in line:
            rvt_ver_pattern = re.compile(r" \d{4} ")
            rvt_file_version = re.search(rvt_ver_pattern, file_info)[0].strip()
            rvt_info["rvt_file_version"] = rvt_file_version
        elif "Last Save Path:" in line:
            rvt_info["LastSavePath"] = line.split()[-1]
        elif "Local Changes Saved To Central:" in line:
            rvt_info["LocalChangesSavedToCentral"] = line.split()[-1]
        elif "Central model's version number:" in line:
            rvt_info["CentralModelVersionNumber"] = line.split()[-1]
        elif "Unique Document GUID:" in line:
            rvt_info["DocGUID"] = line.split()[-1]
        elif "Unique Document Increments:" in line:
            doc_inc = [c for c in line.split()[-1] if c in string.printable][0]
            rvt_info["UniqueDocumentIncrements"] = doc_inc

    return rvt_info


def installed_rvt_detection():
    """
    Finds install path of rvt versions in win registry
    :return:dict: found install paths
    """
    install_location = "InstallLocation"
    rvt_reg_keys = {}
    rvt_install_paths = {}
    index = 0
    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    soft_uninstall = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    python32bit = "32 bit" in sys.version
    python64bit = "64 bit" in sys.version

    if python64bit:
        install_keys = winreg.OpenKey(reg, soft_uninstall)
    elif python32bit:
        install_keys = winreg.OpenKey(reg, soft_uninstall, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)

    while True:
        try:
            adsk_pattern = r"Autodesk Revit ?(\S* )?\d{4}$"
            current_key = winreg.EnumKey(install_keys, index)
            if re.match(adsk_pattern, current_key):
                rvt_reg_keys[current_key] = index
                # print([current_key, index])
        except OSError:
            break
        index += 1

    for rk in rvt_reg_keys.keys():
        version_pattern = r"\d{4}"
        rvt_install_version = re.search(version_pattern, rk)[0]
        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        if python64bit:
            rvt_reg = winreg.OpenKey(reg, soft_uninstall + "\\" + rk)
        elif python32bit:
            rvt_reg = winreg.OpenKey(reg, soft_uninstall + "\\" + rk, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        # print([rk, rvt_reg, install_location])
        exe_location = winreg.QueryValueEx(rvt_reg, install_location)[0] + "Revit.exe"
        rvt_install_paths[rvt_install_version] = exe_location

    return rvt_install_paths
