using System;
using System.Collections.Generic;
using System.Net;

namespace Sres.Net.EEIP
{
    /// <summary>
    /// Represents a CIP route constructed from port/link segments.
    /// Example segments:
    ///  - "1,3" for backplane port 1, slot 3
    ///  - "2,0" for Ethernet port 2
    ///  - "2,192.168.1.10" for extended port segment with IP
    /// </summary>
    public class CIPRoute
    {
        private readonly List<byte> _segments = new List<byte>();

        /// <summary>
        /// Adds a simple 8-bit port and link segment.
        /// </summary>
        public void AddSimpleSegment(byte port, byte link)
        {
            _segments.Add(port);
            _segments.Add(link);
        }

        /// <summary>
        /// Adds an extended segment (IP address).
        /// </summary>
        public void AddExtendedSegment(byte port, IPAddress ip)
        {
            byte[] ipBytes = ip.GetAddressBytes();
            _segments.Add((byte)(0x90 | port));
            _segments.Add((byte)ipBytes.Length);
            _segments.AddRange(ipBytes);
        }

        /// <summary>
        /// Returns the raw CIP route path bytes.
        /// </summary>
        public byte[] GetRoutePathBytes() => _segments.ToArray();

        /// <summary>
        /// Combines route path with Class/Instance/Attribute EPATH.
        /// </summary>
        public byte[] CombineWithEPath(byte[] epath)
        {
            var combined = new List<byte>(_segments);
            combined.AddRange(epath);
            return combined.ToArray();
        }

        /// <summary>
        /// Parses route from comma-separated notation.
        /// e.g. "1,3,2,192.168.1.10"
        /// </summary>
        public static CIPRoute Parse(string routeSpec)
        {
            var route = new CIPRoute();
            var parts = routeSpec.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

            for (int i = 0; i < parts.Length; i += 2)
            {
                byte port = byte.Parse(parts[i].Trim());
                string linkPart = parts[i + 1].Trim();

                if (IPAddress.TryParse(linkPart, out IPAddress ip))
                {
                    route.AddExtendedSegment(port, ip);
                }
                else
                {
                    if (!byte.TryParse(parts[i + 1], out byte link))
                        throw new ArgumentException($"Invalid segment '{parts[i + 1]}'");
                    route.AddSimpleSegment(port, link);
                }
            }

            return route;
        }

        /// <summary>
        /// Returns total length in words (16-bit words) for CIP paths.
        /// </summary>
        public int GetWordCount(byte[] epath)
        {
            int totalBytes = _segments.Count + epath.Length;
            return (totalBytes + 1) / 2;
        }
    }
}
