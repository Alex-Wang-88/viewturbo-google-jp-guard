using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class EngineJob : IDisposable
{
    private const int ExtendedLimitInformation = 9;
    private const uint KillOnJobClose = 0x2000;
    private IntPtr job;

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long PerProcessTime, PerJobTime;
        public uint Flags;
        public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint Priority, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        public BasicLimits Basic;
        public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemory, PeakJobMemory;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int type, ref ExtendedLimits data, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public EngineJob()
    {
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = KillOnJobClose } };
        if (!SetInformationJobObject(job, ExtendedLimitInformation, ref limits, Marshal.SizeOf(typeof(ExtendedLimits))))
        {
            int error = Marshal.GetLastWin32Error();
            Dispose();
            throw new System.ComponentModel.Win32Exception(error);
        }
    }

    public void Add(Process process)
    {
        if (!AssignProcessToJobObject(job, process.Handle))
            throw new System.ComponentModel.Win32Exception();
    }

    public void Dispose()
    {
        if (job == IntPtr.Zero) return;
        CloseHandle(job);
        job = IntPtr.Zero;
    }
}

public sealed class LinkWatch : IDisposable
{
    private int version;
    public LinkWatch() { NetworkChange.NetworkAddressChanged += Changed; }
    public int Version { get { return Volatile.Read(ref version); } }
    private void Changed(object sender, EventArgs args) { Interlocked.Increment(ref version); }
    public void Dispose() { NetworkChange.NetworkAddressChanged -= Changed; }
}
