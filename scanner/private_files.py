"""Diretório privado criado com ACL antes de qualquer conteúdo restrito."""
import os
from pathlib import Path


def private_directory(path):
    path = Path(path)
    if os.name != 'nt':
        path.mkdir(mode=0o700)
        return path
    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', wintypes.LPVOID), ('inherit', wintypes.BOOL)]

    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    create = kernel.CreateDirectoryW
    create.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    create.restype = wintypes.BOOL
    descriptor = wintypes.LPVOID()
    # Owner Rights + SYSTEM. Herança protegida: nenhum grupo externo do pai.
    if not convert('D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)', 1, ctypes.byref(descriptor), None):
        raise OSError('Não foi possível preparar permissões restritas.')
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not create(str(path.resolve()), ctypes.byref(attributes)):
            raise OSError('Não foi possível criar diretório restrito.')
    finally:
        kernel.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel.LocalFree(descriptor)
    return path
