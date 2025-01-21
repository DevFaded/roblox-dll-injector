import ctypes
import time
import threading
from ctypes import wintypes

# constants
PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPPROCESS = 0x00000002
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
WH_GETMESSAGE = 3
WM_NULL = 0x0000

# structures
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', wintypes.ULONG),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', ctypes.c_long),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', ctypes.c_char * 260)
    ]

# imports
kernel32 = ctypes.WinDLL('kernel32')
user32 = ctypes.WinDLL('user32')

def open_process(desired_access, inherit_handle, process_id):
    return kernel32.OpenProcess(desired_access, inherit_handle, process_id)

def create_toolhelp32_snapshot(flags, process_id):
    return kernel32.CreateToolhelp32Snapshot(flags, process_id)

def process32_first(snapshot, entry):
    return kernel32.Process32First(snapshot, ctypes.byref(entry))

def process32_next(snapshot, entry):
    return kernel32.Process32Next(snapshot, ctypes.byref(entry))

def find_window(class_name, window_name):
    return user32.FindWindowW(class_name, window_name)

def is_window_visible(hWnd):
    return user32.IsWindowVisible(hWnd)

def get_window_thread_process_id(hWnd):
    process_id = wintypes.DWORD()
    thread_id = user32.GetWindowThreadProcessId(hWnd, ctypes.byref(process_id))
    return thread_id, process_id.value

def virtual_protect_ex(process, address, size, new_protect):
    old_protect = wintypes.DWORD()
    result = kernel32.VirtualProtectEx(process, address, size, new_protect, ctypes.byref(old_protect))
    return result, old_protect.value

def write_process_memory(process, base_address, buffer):
    bytes_written = ctypes.c_size_t()
    result = kernel32.WriteProcessMemory(process, base_address, buffer, len(buffer), ctypes.byref(bytes_written))
    return result, bytes_written.value

def load_library(library_name):
    return kernel32.LoadLibraryA(library_name.encode('ascii'))

def get_proc_address(module, proc_name):
    return kernel32.GetProcAddress(module, proc_name.encode('ascii'))

def set_windows_hook_ex(id_hook, func, module, thread_id):
    return user32.SetWindowsHookExW(id_hook, func, module, thread_id)

def post_thread_message(thread_id, msg, w_param, l_param):
    return user32.PostThreadMessageW(thread_id, msg, w_param, l_param)

def show_window(hWnd, nCmdShow):
    return user32.ShowWindow(hWnd, nCmdShow)

def get_process_id(process_name):
    snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if process32_first(snapshot, entry):
            while True:
                if entry.szExeFile.decode('ascii').lower() == process_name.lower():
                    return entry.th32ProcessID
                if not process32_next(snapshot, entry):
                    break
    return 0

def main():
    print("Waiting for Roblox process...")

    while True:
        hWnd = find_window(None, "Roblox")
        if is_window_visible(hWnd):
            break
        time.sleep(0.1)

    print("Roblox process found.")

    def monitor_exit():
        while True:
            if find_window(None, "Roblox") == 0:
                exit()
            time.sleep(0.1)

    threading.Thread(target=monitor_exit, daemon=True).start()

    process_id = get_process_id("RobloxPlayerBeta.exe")
    process_handle = open_process(PROCESS_ALL_ACCESS, False, process_id)

    wintrust_module = load_library("wintrust.dll")
    win_verify_trust = get_proc_address(wintrust_module, "WinVerifyTrust")

    payload = bytes([0x48, 0x31, 0xC0, 0x59, 0xFF, 0xE1])

    success, old_protect = virtual_protect_ex(process_handle, win_verify_trust, len(payload), PAGE_EXECUTE_READWRITE)
    if not success:
        print("Failed to protect WinVerifyTrust.")

    success, _ = write_process_memory(process_handle, win_verify_trust, payload)
    if not success:
        print("Failed to patch WinVerifyTrust.")

    success, _ = virtual_protect_ex(process_handle, win_verify_trust, len(payload), PAGE_EXECUTE_READ)
    if not success:
        print("Failed to restore protection.")

    thread_id, _ = get_window_thread_process_id(hWnd)

    target_module = load_library("paradise.dll")
    if not target_module:
        print("Failed to load module.")

    dll_export = get_proc_address(target_module, "NextHook") # if ur to skiddy change this to ur export name
    if not dll_export:
        print("Failed to find module hook.")

    hook_handle = set_windows_hook_ex(WH_GETMESSAGE, dll_export, target_module, thread_id)
    if not hook_handle:
        print("Failed to set module hook.")

    if not post_thread_message(thread_id, WM_NULL, 0, 0):
        print("Failed to post thread message.")

    print("Module attached successfully.")
    
    hWnd = ctypes.windll.kernel32.GetConsoleWindow()
    show_window(hWnd, 6)  # SW_FORCEMINIMIZE

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
