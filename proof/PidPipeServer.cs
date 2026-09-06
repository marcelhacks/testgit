using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

internal static class PidPipeServer
{
    private const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    private const uint PIPE_TYPE_BYTE = 0x00000000;
    private const uint PIPE_READMODE_BYTE = 0x00000000;
    private const uint PIPE_WAIT = 0x00000000;
    private const int ERROR_PIPE_CONNECTED = 535;
    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string descriptor, uint revision, out IntPtr securityDescriptor, out uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateNamedPipe(
        string name, uint openMode, uint pipeMode, uint maxInstances,
        uint outBufferSize, uint inBufferSize, uint defaultTimeout,
        ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientPid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DisconnectNamedPipe(IntPtr pipe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static int Main()
    {
        IntPtr descriptor;
        uint descriptorSize;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                "D:(A;;GA;;;AU)", 1, out descriptor, out descriptorSize))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        var attributes = new SecurityAttributes {
            Length = Marshal.SizeOf(typeof(SecurityAttributes)),
            SecurityDescriptor = descriptor,
            InheritHandle = 0
        };

        IntPtr pipe = CreateNamedPipe(
            @"\\.\pipe\PidSpoofProof", PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1,
            65536, 65536, 0, ref attributes);
        LocalFree(descriptor);
        if (pipe == InvalidHandleValue)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        try {
            bool connected = ConnectNamedPipe(pipe, IntPtr.Zero);
            int error = Marshal.GetLastWin32Error();
            if (!connected && error != ERROR_PIPE_CONNECTED)
                throw new Win32Exception(error);

            uint pid;
            if (!GetNamedPipeClientProcessId(pipe, out pid))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            Console.WriteLine("OBSERVED_CLIENT_PID=" + pid);
            Console.Out.Flush();
            Thread.Sleep(1000);
            return 0;
        }
        finally {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }
}
