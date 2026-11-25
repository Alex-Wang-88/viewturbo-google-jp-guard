using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class PacketGuard
{
    private static readonly Guid RuleSet = new Guid("dc1e4d6e-63fc-4595-a845-31b8b579e306");
    private static readonly Guid[] Outbound = {
        new Guid("1e5c9fae-8a84-4135-a331-950b54229ecd"),
        new Guid("a3b3ab6b-3564-488c-9117-f34e82142763")
    };
    private static readonly Guid[] Forward = {
        new Guid("a82acc24-4ee1-4ee1-b465-fd1d25cb10a4"),
        new Guid("7b964818-19c7-493a-b71f-832c3684d28c")
    };
    private static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid DestinationAddress = new Guid("2d79133b-b390-45c6-8699-acaceaafed33");
    private static readonly Guid LocalInterface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    private static readonly Guid[] Connect = {
        new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"),
        new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")
    };
    private static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    private static readonly Guid PacketFlags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
    private static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");

    private const uint Persistent = 1;
    private const uint BootTime = 2;
    private const uint DynamicSession = 1;
    private const uint Block = 0x1001;
    private const uint Permit = 0x1002;
    private const uint FilterNotFound = 0x80320003;
    private const uint SublayerNotFound = 0x80320007;
    private const uint AlreadyExists = 0x80320009;
    private const uint UInt8 = 1;
    private const uint UInt16 = 2;
    private const uint UInt32 = 3;
    private const uint UInt64 = 4;
    private const uint ByteBlob = 12;
    private const uint V4Mask = 256;
    private const uint V6Mask = 257;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Display
    {
        public string Name;
        public string Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Blob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Sublayer
    {
        public Guid Key;
        public Display Display;
        public uint Flags;
        public IntPtr Provider;
        public Blob Data;
        public ushort Weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Value
    {
        public uint Type;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Condition
    {
        public Guid Field;
        public uint Match;
        public Value Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FilterAction
    {
        public uint Type;
        public Guid Key;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FilterContext
    {
        [FieldOffset(0)] public ulong Raw;
        [FieldOffset(0)] public Guid Provider;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Filter
    {
        public Guid Key;
        public Display Display;
        public uint Flags;
        public IntPtr Provider;
        public Blob Data;
        public Guid Layer;
        public Guid Sublayer;
        public Value Weight;
        public uint Count;
        public IntPtr Conditions;
        public FilterAction Action;
        public FilterContext Context;
        public IntPtr Reserved;
        public ulong Id;
        public Value EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Session
    {
        public Guid Key;
        public Display Display;
        public uint Flags;
        public uint Timeout;
        public uint Pid;
        public IntPtr Sid;
        public IntPtr User;
        public int KernelMode;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr identity,
        ref Session session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer layer, IntPtr sd);
    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr sd, out ulong id);
    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
    [DllImport("fwpuclnt.dll")] private static extern void FwpmFreeMemory0(ref IntPtr item);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint FwpmGetAppIdFromFileName0(string path, out IntPtr appId);
    [DllImport("iphlpapi.dll")]
    private static extern uint ConvertInterfaceIndexToLuid(uint index, out ulong luid);

    private static void Check(uint result, string operation)
    {
        if (result != 0)
            throw new InvalidOperationException(operation + " failed (0x" + result.ToString("x8") + ").");
    }

    private static Guid Key(Guid layer, string item, uint flags)
    {
        using (var sha = SHA256.Create())
        {
            byte[] input = Encoding.ASCII.GetBytes(RuleSet + "|" + layer + "|" + item + "|" + flags);
            byte[] guid = new byte[16];
            Array.Copy(sha.ComputeHash(input), guid, guid.Length);
            return new Guid(guid);
        }
    }

    private static Display Label(string name)
    {
        return new Display { Name = "Google JP Guard: " + name };
    }

    private static IntPtr Open(bool temporary)
    {
        var session = new Session { Display = Label("WFP"), Flags = temporary ? DynamicSession : 0, Timeout = 5000 };
        IntPtr engine;
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out engine), "Open WFP");
        return engine;
    }

    private static void Transaction(IntPtr engine, Action update)
    {
        Check(FwpmTransactionBegin0(engine, 0), "Begin WFP transaction");
        try
        {
            update();
            Check(FwpmTransactionCommit0(engine), "Commit WFP transaction");
        }
        catch
        {
            FwpmTransactionAbort0(engine);
            throw;
        }
    }

    private static void Add(IntPtr engine, Guid layer, Guid match, uint dataType, IntPtr value,
        string label, uint flags, uint action, byte weight)
    {
        Add(engine, layer, new[] { Match(match, dataType, value) }, label, flags, action, weight);
    }

    private static Condition Match(Guid field, uint type, IntPtr value, uint comparison = 0)
    {
        return new Condition { Field = field, Match = comparison, Value = new Value { Type = type, Data = value } };
    }

    private static void Add(IntPtr engine, Guid layer, Condition[] conditions, string label, uint flags, uint action, byte weight)
    {
        int size = Marshal.SizeOf(typeof(Condition));
        IntPtr data = Marshal.AllocHGlobal(size * conditions.Length);
        try
        {
            for (int i = 0; i < conditions.Length; i++)
                Marshal.StructureToPtr(conditions[i], IntPtr.Add(data, i * size), false);
            var filter = new Filter
            {
                Key = Key(layer, label, flags),
                Display = Label(label),
                Flags = flags,
                Layer = layer,
                Sublayer = RuleSet,
                Weight = new Value { Type = UInt8, Data = new IntPtr(weight) },
                Count = (uint)conditions.Length,
                Conditions = data,
                Action = new FilterAction { Type = action }
            };
            ulong id;
            uint result = FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id);
            if (result != AlreadyExists) Check(result, "Add WFP filter " + label);
        }
        finally { Marshal.FreeHGlobal(data); }
    }

    private static void ForPrefix(IntPtr engine, string prefix, IntPtr coreApp, bool install)
    {
        string[] parts = prefix.Split('/');
        byte[] address = IPAddress.Parse(parts[0]).GetAddressBytes();
        int bits = int.Parse(parts[1]);
        int family = address.Length == 4 ? 0 : 1;
        if (bits <= 0 || bits > address.Length * 8) throw new FormatException("Invalid policy prefix");
        if (!install)
        {
            foreach (uint flags in new[] { Persistent, BootTime })
            {
                Delete(engine, Key(Outbound[family], prefix, flags));
                Delete(engine, Key(Forward[family], prefix, flags));
            }
            Delete(engine, Key(Connect[family], "Core direct " + prefix, Persistent));
            return;
        }
        IntPtr network = Marshal.AllocHGlobal(family == 0 ? 8 : 17);
        try
        {
            if (family == 0)
            {
                uint addr = ((uint)address[0] << 24) | ((uint)address[1] << 16) |
                    ((uint)address[2] << 8) | address[3];
                Marshal.WriteInt32(network, unchecked((int)addr));
                Marshal.WriteInt32(network, 4, unchecked((int)(uint.MaxValue << (32 - bits))));
            }
            else
            {
                Marshal.Copy(address, 0, network, 16);
                Marshal.WriteByte(network, 16, (byte)bits);
            }
            uint dataType = family == 0 ? V4Mask : V6Mask;
            foreach (uint flags in new[] { Persistent, BootTime })
            {
                Add(engine, Outbound[family], RemoteAddress, dataType, network, prefix, flags, Block, 8);
                Add(engine, Forward[family], DestinationAddress, dataType, network, prefix, flags, Block, 8);
            }
            // A direct decision by ViewTurbo must not escape or recurse into the selective TUN.
            Add(engine, Connect[family], new[] {
                Match(RemoteAddress, dataType, network),
                Match(AppId, ByteBlob, coreApp)
            }, "Core direct " + prefix, Persistent, Block, 8);
        }
        finally { Marshal.FreeHGlobal(network); }
    }

    private static void Delete(IntPtr engine, Guid key)
    {
        uint result = FwpmFilterDeleteByKey0(engine, ref key);
        if (result != FilterNotFound) Check(result, "Delete WFP filter");
    }

    private static Condition[] LocalProxy(ushort proxyPort, IntPtr app)
    {
        var port = Match(RemotePort, UInt16, new IntPtr(proxyPort));
        // FWP_MATCH_FLAGS_ALL_SET, FWP_CONDITION_FLAG_IS_LOOPBACK.
        var loopback = Match(PacketFlags, UInt32, new IntPtr(1), 6);
        return app == IntPtr.Zero ? new[] { port, loopback } :
            new[] { port, loopback, Match(AppId, ByteBlob, app) };
    }

    public static void SetRules(string[] prefixes, ushort proxyPort, string corePath, bool install)
    {
        IntPtr engine = Open(false);
        IntPtr app = IntPtr.Zero;
        try
        {
            if (install) Check(FwpmGetAppIdFromFileName0(corePath, out app), "Read ViewTurbo app ID");
            Transaction(engine, delegate
            {
                if (install)
                {
                    var layer = new Sublayer { Key = RuleSet, Display = Label("Google destinations"), Flags = Persistent, Weight = 0xe000 };
                    uint result = FwpmSubLayerAdd0(engine, ref layer, IntPtr.Zero);
                    if (result != AlreadyExists) Check(result, "Add WFP sublayer");
                }
                foreach (string prefix in prefixes) ForPrefix(engine, prefix, app, install);
                foreach (Guid layer in Connect)
                {
                    const string label = "ViewTurbo loopback";
                    if (install) Add(engine, layer, LocalProxy(proxyPort, IntPtr.Zero), label, Persistent, Block, 8);
                    else Delete(engine, Key(layer, label, Persistent));
                }
                if (!install)
                {
                    Guid key = RuleSet;
                    uint result = FwpmSubLayerDeleteByKey0(engine, ref key);
                    if (result != SublayerNotFound) Check(result, "Delete WFP sublayer");
                }
            });
        }
        finally
        {
            if (app != IntPtr.Zero) FwpmFreeMemory0(ref app);
            FwpmEngineClose0(engine);
        }
    }

    private static bool Exists(IntPtr engine, Guid key)
    {
        IntPtr data;
        uint result = FwpmFilterGetByKey0(engine, ref key, out data);
        if (result == FilterNotFound) return false;
        Check(result, "Read WFP filter");
        FwpmFreeMemory0(ref data);
        return true;
    }

    public static bool HasRules(string[] prefixes)
    {
        IntPtr engine = Open(false);
        try
        {
            foreach (string prefix in prefixes)
            {
                int family = prefix.Contains(":") ? 1 : 0;
                foreach (Guid layer in new[] { Outbound[family], Forward[family] })
                {
                    if (!Exists(engine, Key(layer, prefix, Persistent))) return false;
                }
                if (!Exists(engine, Key(Connect[family], "Core direct " + prefix, Persistent))) return false;
            }
            foreach (Guid layer in Connect)
                if (!Exists(engine, Key(layer, "ViewTurbo loopback", Persistent))) return false;
            return true;
        }
        finally { FwpmEngineClose0(engine); }
    }

    public static IntPtr AllowEngine(ushort proxyPort, string executable)
    {
        IntPtr engine = Open(true);
        IntPtr app = IntPtr.Zero;
        try
        {
            Check(FwpmGetAppIdFromFileName0(executable, out app), "Read engine app ID");
            Transaction(engine, delegate
            {
                foreach (Guid layer in Connect)
                    Add(engine, layer, LocalProxy(proxyPort, app), "Engine proxy permission", 0, Permit, 12);
            });
            return engine;
        }
        catch
        {
            FwpmEngineClose0(engine);
            throw;
        }
        finally { if (app != IntPtr.Zero) FwpmFreeMemory0(ref app); }
    }

    public static IntPtr AllowTun(uint index)
    {
        ulong luid;
        Check(ConvertInterfaceIndexToLuid(index, out luid), "Read TUN interface LUID");
        IntPtr engine = Open(true);
        IntPtr value = Marshal.AllocHGlobal(8);
        try
        {
            Marshal.WriteInt64(value, unchecked((long)luid));
            Transaction(engine, delegate
            {
                foreach (Guid layer in Outbound)
                    Add(engine, layer, LocalInterface, UInt64, value, "TUN " + luid, 0, Permit, 12);
            });
            return engine;
        }
        catch
        {
            FwpmEngineClose0(engine);
            throw;
        }
        finally { Marshal.FreeHGlobal(value); }
    }

    public static void Close(IntPtr handle)
    {
        if (handle != IntPtr.Zero) Check(FwpmEngineClose0(handle), "Close WFP dynamic session");
    }
}
