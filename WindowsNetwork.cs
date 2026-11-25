using System;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

public static class WindowsNetwork
{
    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestInterface(uint address, out uint index);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int length, bool sort,
        int addressFamily, int tableClass, uint reserved);

    [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr value, int length);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProxyOption
    {
        public int Id;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProxyOptionList
    {
        public int Size;
        public IntPtr Connection;
        public int Count;
        public int ErrorIndex;
        public IntPtr Options;
    }

    public static int ViewTurboTunIndex()
    {
        // ViewTurbo Lite routes 44.0.0.0/8 through its own Wintun when it is active.
        uint routeIndex;
        uint target = BitConverter.ToUInt32(IPAddress.Parse("44.0.0.1").GetAddressBytes(), 0);
        if (GetBestInterface(target, out routeIndex) != 0) return 0;
        foreach (var item in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!item.Name.Equals("wintun", StringComparison.OrdinalIgnoreCase) ||
                !item.Description.StartsWith("tun2socks Tunnel", StringComparison.OrdinalIgnoreCase) ||
                item.OperationalStatus != OperationalStatus.Up) continue;
            var addressProperties = item.GetIPProperties().GetIPv4Properties();
            if (addressProperties != null && addressProperties.Index == routeIndex)
                return addressProperties.Index;
        }
        return 0;
    }

    private static int FindLoopbackListener(int family, int port)
    {
        const int ownerPidListener = 3;
        const uint insufficientBuffer = 122;
        int length = 0;
        uint result = GetExtendedTcpTable(IntPtr.Zero, ref length, false, family, ownerPidListener, 0);
        if (result != insufficientBuffer || length < 4) return 0;
        int rowSize = family == 2 ? 24 : 56;
        int addressOffset = family == 2 ? 4 : 0;
        int portOffset = family == 2 ? 8 : 20;
        int pidOffset = family == 2 ? 20 : 52;
        IntPtr table = Marshal.AllocHGlobal(length);
        try
        {
            int capacity = length;
            if (GetExtendedTcpTable(table, ref length, false, family, ownerPidListener, 0) != 0) return 0;
            int count = Marshal.ReadInt32(table);
            if (count < 0 || count > (capacity - 4) / rowSize) return 0;
            for (int i = 0; i < count; i++)
            {
                IntPtr row = IntPtr.Add(table, 4 + i * rowSize);
                if ((Marshal.ReadByte(row, portOffset) << 8 | Marshal.ReadByte(row, portOffset + 1)) != port)
                    continue;
                int width = family == 2 ? 4 : 16;
                byte[] bytes = new byte[width];
                Marshal.Copy(IntPtr.Add(row, addressOffset), bytes, 0, width);
                var address = new IPAddress(bytes);
                if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                    return Marshal.ReadInt32(row, pidOffset);
            }
            return 0;
        }
        finally { Marshal.FreeHGlobal(table); }
    }

    public static int LoopbackListener(int port)
    {
        int pid = FindLoopbackListener(2, port);
        return pid != 0 ? pid : FindLoopbackListener(23, port);
    }

    public static void SetProxyServer(string server)
    {
        var value = new ProxyOption { Id = 2, Value = Marshal.StringToHGlobalUni(server) };
        IntPtr option = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ProxyOption)));
        int size = Marshal.SizeOf(typeof(ProxyOptionList));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(value, option, false);
            Marshal.StructureToPtr(new ProxyOptionList { Size = size, Count = 1, Options = option }, buffer, false);
            // Update only INTERNET_PER_CONN_PROXY_SERVER. Leave proxy enable, PAC and bypass flags untouched.
            if (!InternetSetOption(IntPtr.Zero, 75, buffer, size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            InternetSetOption(IntPtr.Zero, 95, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            Marshal.FreeHGlobal(option);
            Marshal.FreeHGlobal(value.Value);
        }
    }
}
