using System;
using System.Collections.Generic;
using System.Text;

namespace AuthurGenesis.Foundation.Fountainhead
{
    public readonly struct Device
    {
        public static Device Empty { get; } = new Device();
        public string? IDCode { get; init; }
        public string? SubCode { get; init; }
        public string? ProtocolCode { get; init; }
        public string? DeviceMark { get; init; }
        public override string ToString()
        {
            return IDCode + "_" + SubCode + "_" + ProtocolCode;
        }
        public static Device Parse(ReadOnlySpan<char> name)
        {
            if (name.IsEmpty) return Empty;
            var parts = name.ToString().Split('#');
            if (parts.Length == 0) return Empty;
            return new Device
            {
                DeviceMark = parts[0].ToString().Replace('\\', ' ').Replace('?', ' ').Trim(),
                IDCode = parts.Length > 1 ? parts[1].ToString() : string.Empty,
                SubCode = parts.Length > 2 ? parts[2].ToString() : string.Empty,
                ProtocolCode = parts.Length > 3 ? parts[3].ToString().Trim() : string.Empty
            };
        }
    }
}

