#pragma warning disable CA1416
using AuthurGenesis.Foundation.Fountainhead;
using System.Buffers;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.UI.Input;
using Windows.Win32.UI.WindowsAndMessaging;

namespace AuthurGenesis.Foundation
{

    [SupportedOSPlatform("windows")]
    public class ScannerBase : IDisposable
    {
        private readonly object _lock = new();
        private readonly ConcurrentDictionary<string, Device> _devices;
        private readonly StringBuilder _stringBuffer;
        private readonly WNDPROC _proc;
        private readonly CancellationTokenSource _cts = new();
        private readonly string _className;
        private IntPtr _lpClassName;
        private bool _classRegistered;
        private bool _rawInputRegistered;
        private HWND _hwnd;
        private HMODULE _instance;
        private Thread? _messageThread;
        private volatile bool _disposed;
        public string? TargetDeviceId { get; set; }
        public event Action<string>? CardScanned;
        public event Action<Device>? DeviceInserted;
        public ScannerBase()
        {
            _stringBuffer = new(128);
            _className = $"AuthurScanner_{Guid.NewGuid():N}";
            _lpClassName = Marshal.StringToCoTaskMemUni(_className);
            _proc = AuthurProc;
            _devices = new();
            _instance = Authur.GetModuleHandle(new PCWSTR());
            EnumerateExistingDevices();
        }

        public List<Device>? GetDevicesList()
        {
            return _devices.Values.ToList<Device>();
        }
        private unsafe void EnumerateExistingDevices()
        {
            uint count = 0;
            uint size = (uint)sizeof(RAWINPUTDEVICELIST);
            Authur.GetRawInputDeviceList(null, &count, size);
            var list = ArrayPool<RAWINPUTDEVICELIST>.Shared.Rent((int)count);
            try
            {
                fixed (RAWINPUTDEVICELIST* ptr = list)
                {
                    Authur.GetRawInputDeviceList(ptr, &count, size);
                    for (int i = 0; i < count; i++)
                    {
                        var device = ParseDevice(list[i].hDevice);
                        if (!string.IsNullOrEmpty(device.IDCode))
                        {
                            _devices[device.IDCode] = device;
                        }
                    }
                }
            }
            finally
            {
                ArrayPool<RAWINPUTDEVICELIST>.Shared.Return(list);
            }


        }
        private unsafe Device ParseDevice(HANDLE handle)
        {
            uint length = 0;
            Authur.GetRawInputDeviceInfo(handle, RAW_INPUT_DEVICE_INFO_COMMAND.RIDI_DEVICENAME, null, &length);
            if (length == 0) return Device.Empty;
            var buffer = ArrayPool<char>.Shared.Rent((int)length);
            try
            {
                fixed (char* pBuffer = buffer)
                {
                    Authur.GetRawInputDeviceInfo(handle, RAW_INPUT_DEVICE_INFO_COMMAND.RIDI_DEVICENAME, pBuffer, &length);
                    var deviceName = new string(pBuffer, 0, (int)length - 1);
                    return Device.Parse(deviceName.AsSpan());
                }
            }
            finally
            {
                ArrayPool<char>.Shared.Return(buffer);
            }
        }
        public void StartMonitor()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ScannerBase));
            }
            lock (_lock)
            {
                if (_messageThread is { IsAlive: true }) return;
                _messageThread = new Thread(RunMessageLoop) { IsBackground = true, Name = $"{nameof(ScannerBase)}.MessageLoop" };
                _messageThread.Start();
            }
        }
        public void stopMonitor()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ScannerBase));
            }
            lock (_lock)
            {
                if (_messageThread is not { IsAlive: true }) return;
                _cts.Cancel();
                if (_hwnd != HWND.Null)
                {
                    Authur.PostMessage(_hwnd, 0x0010, 0, 0);
                }
                _messageThread.Join(2000);

            }
        }
        private void RunMessageLoop()
        {
            try
            {
                CreateWindowAndRegisterRawInput();
                PumpMessages();
            }
            catch (OperationCanceledException)
            {

            }
            finally
            {
                ReleaseNativeResources();
            }
        }
        private unsafe void CreateWindowAndRegisterRawInput()
        {
            fixed (char* name = _className)
            {
                var wc = new WNDCLASSEXW
                {
                    cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
                    lpszClassName = new PCWSTR(name),
                    hInstance = _instance,
                    lpfnWndProc = _proc
                };
                if (Authur.RegisterClassEx(wc) == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                _classRegistered = true;
                _hwnd = Authur.CreateWindowEx(
                    dwExStyle: 0,
                    lpClassName: new PCWSTR(name),
                    lpWindowName: new PCWSTR(name),
                    dwStyle: WINDOW_STYLE.WS_POPUP,
                    0, 0, 0, 0,
                    hWndParent: HWND.Null,
                    hMenu: HMENU.Null,
                    hInstance: _instance);
                if (_hwnd == HWND.Null)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                RegisterRawInput();
            }
        }
        private unsafe void RegisterRawInput()
        {
            var device = new RAWINPUTDEVICE()
            {
                usUsagePage = Authur.HID_USAGE_PAGE_GENERIC,
                usUsage = Authur.HID_USAGE_GENERIC_KEYBOARD,
                dwFlags = RAWINPUTDEVICE_FLAGS.RIDEV_INPUTSINK | RAWINPUTDEVICE_FLAGS.RIDEV_DEVNOTIFY | RAWINPUTDEVICE_FLAGS.RIDEV_NOLEGACY,
                hwndTarget = _hwnd
            };
            RAWINPUTDEVICE[] devices = new RAWINPUTDEVICE[] { device };
            fixed (RAWINPUTDEVICE* pDevices = devices)
            {
                if (!Authur.RegisterRawInputDevices(pDevices, (uint)devices.Length, (uint)sizeof(RAWINPUTDEVICE)))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                _rawInputRegistered = true;
            }
        }
        private LRESULT AuthurProc(HWND hwnd, uint msg, WPARAM wParam, LPARAM lParam)
        {
            if (_cts.IsCancellationRequested) return Authur.DefWindowProc(hwnd, msg, wParam, lParam);
            switch (msg)
            {
                case Authur.WM_INPUT:
                    ProcessRawinputMessage(lParam);
                    return new LRESULT(0);
                case Authur.WM_INPUT_DEVICE_CHANGE when wParam == Authur.GIDC_ARRIVAL:
                    var device = ParseDevice(new HANDLE(lParam));
                    if (device.IDCode is not null)
                    {
                        _devices.TryAdd(device.IDCode, device);
                        DeviceInserted?.Invoke(device);
                    }
                    return new LRESULT(0);
                case Authur.WM_DESTROY:
                    _cts.Cancel();
                    Authur.PostQuitMessage(0);
                    return new LRESULT(0);
            }
            return Authur.DefWindowProc(hwnd, msg, wParam, lParam);
        }

        private void ProcessRawinputMessage(LPARAM lParam)
        {
            RAWINPUT rawInput = GetRawInput(lParam);
            if (rawInput.header.dwType != 1) return;

            var kb = rawInput.data.keyboard;

            if ((kb.Flags & 0x01) != 0) return;

            var device = ParseDevice(rawInput.header.hDevice);
            if (!device.IDCode.Contains(TargetDeviceId ?? string.Empty, StringComparison.OrdinalIgnoreCase))
                return;
            if (kb.VKey == 13)
            {
                var data = _stringBuffer.ToString();
                if (data.Length > 0)
                    CardScanned?.Invoke(data);
                _stringBuffer.Clear();
            }
            else if (kb.VKey is >= 0x30 and < 0x5A)
            {
                _stringBuffer.Append((char)kb.VKey);
            }
        }
        private unsafe RAWINPUT GetRawInput(LPARAM lParam)
        {
            uint size = 0, headerSize = (uint)sizeof(RAWINPUTHEADER);
            var hRaw = new HRAWINPUT(lParam);
            var requiredSize = Authur.GetRawInputData(hRaw, RAW_INPUT_DATA_COMMAND_FLAGS.RID_INPUT, null, &size, headerSize);
            if (requiredSize == unchecked((uint)-1) || size < sizeof(RAWINPUT))
                return default;

            var buffer = ArrayPool<byte>.Shared.Rent((int)size);
            try
            {
                fixed (byte* pbuffer = buffer)
                {
                    var res = Authur.GetRawInputData(hRaw, RAW_INPUT_DATA_COMMAND_FLAGS.RID_INPUT, pbuffer, &size, headerSize);
                    return res == unchecked((uint)-1) || size < sizeof(RAWINPUT)
                        ? default
                        : *(RAWINPUT*)pbuffer;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        private void PumpMessages()
        {
            while (Authur.GetMessage(out MSG msg, _hwnd, 0, 0) != 0)
            {
                Authur.TranslateMessage(msg);
                Authur.DispatchMessage(msg);
            }
        }
        ~ScannerBase()
        {
            Dispose();
        }
        public void Dispose()
        {
            Thread? messageThread;
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
                _cts.Cancel();
                if (_hwnd != HWND.Null)
                {
                    Authur.PostMessage(_hwnd, 0x0010, 0, 0);
                }
                messageThread = _messageThread;
            }

            if (messageThread is not null && messageThread != Thread.CurrentThread)
            {
                messageThread.Join(2000);
            }

            CardScanned = null;
            DeviceInserted = null;
            if (messageThread is null || !messageThread.IsAlive)
            {
                ReleaseNativeResources();
                _cts.Dispose();
            }
            GC.SuppressFinalize(this);
        }
        private unsafe void ReleaseNativeResources()
        {
            if (_hwnd != HWND.Null && _rawInputRegistered)
            {
                var device = new RAWINPUTDEVICE()
                {
                    usUsagePage = Authur.HID_USAGE_PAGE_GENERIC,
                    usUsage = Authur.HID_USAGE_GENERIC_KEYBOARD,
                    dwFlags = RAWINPUTDEVICE_FLAGS.RIDEV_REMOVE,
                    hwndTarget = HWND.Null
                };
                Authur.RegisterRawInputDevices(&device, 1, (uint)sizeof(RAWINPUTDEVICE));
                _rawInputRegistered = false;
            }

            if (_hwnd != HWND.Null)
            {
                Authur.DestroyWindow(_hwnd);
                _hwnd = HWND.Null;

            }

            if (_classRegistered)
            {
                fixed (char* pClassName = _className)
                {
                    Authur.UnregisterClass(new PCWSTR(pClassName), _instance);
                }
                _classRegistered = false;
            }

            if (_lpClassName != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(_lpClassName);
                _lpClassName = IntPtr.Zero;
            }
            _devices.Clear();
            _stringBuffer.Clear();
        }
    }

}
