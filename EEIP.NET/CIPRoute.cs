using System;
using System.Collections.Generic;
using System.Net;

namespace Sres.Net.EEIP
{
    /// <summary>
    /// Base class for CIP segments.
    /// </summary>
    public abstract class CIPSegment
    {
        /// <summary>
        /// Encodes the segment into its binary representation.
        /// </summary>
        public abstract byte[] Encode();
    }

    /// <summary>
    /// Represents a port segment of a CIP path.
    /// 
    /// +----+----+----+--------------------+----+----+----+----+
    /// | Segment Type | Extended Link Addr | Port Identifier   |
    /// +====+====+====+====================+====+====+====+====+
    /// |  7 |  6 | 5  |         4          |  3 |  2 |  1 |  0 |
    /// +----+----+----+--------------------+----+----+----+----+
    /// 
    /// For extended segments (when the link is an IP address), the first byte is generated as:
    ///     (0x90 | port)
    /// then the next byte is the length (typically 4 for IPv4), followed by the IP address bytes.
    /// For a simple segment, the two bytes are: [port, link].
    /// </summary>
    public class PortSegment : CIPSegment
    {
        public byte PortValue { get; private set; }
        public string LinkValue { get; private set; }
        public bool IsExtended { get; private set; }

        // For extended segments, 0x90 is used as the base.
        public const byte ExtendedBase = 0x90;

        // Dictionary mapping well-known port names to their numeric values.
        private static readonly Dictionary<string, byte> PortNames = new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase)
        {
            { "backplane", 0x01 },
            { "bp", 0x01 },
            { "enet", 0x02 },
            { "dhrio-a", 0x02 },
            { "dhrio-b", 0x03 },
            { "dnet", 0x02 },
            { "cnet", 0x02 },
            { "dh485-a", 0x02 },
            { "dh485-b", 0x03 }
        };

        /// <summary>
        /// Creates a new PortSegment.
        /// </summary>
        /// <param name="port">
        /// Either a numeric port (e.g., 2) or a string key (e.g., "bp", "enet").
        /// </param>
        /// <param name="link">
        /// The link portion, which can be a numeric string (for simple segments) or an IP address string (for extended segments).
        /// </param>
        public PortSegment(object port, string link)
        {
            // Convert the port to a byte.
            if (port is int intPort)
            {
                PortValue = Convert.ToByte(intPort);
            }
            else if (port is string s)
            {
                if (!PortNames.TryGetValue(s, out byte val))
                    throw new ArgumentException($"Unknown port name: {s}");
                PortValue = val;
            }
            else
            {
                throw new ArgumentException("Port must be an integer or a string");
            }

            LinkValue = link;
            // If the link parses as an IP address, consider this an extended segment.
            IsExtended = IPAddress.TryParse(link, out _);
        }

        /// <summary>
        /// Encodes the PortSegment into its binary representation.
        /// </summary>
        public override byte[] Encode()
        {
            if (IsExtended)
            {
                // For an extended segment, the first byte is (ExtendedBase OR port).
                byte firstByte = (byte)(ExtendedBase | PortValue);
                IPAddress ip = IPAddress.Parse(LinkValue);
                byte[] ipBytes = ip.GetAddressBytes();
                byte lengthByte = (byte)ipBytes.Length;
                byte[] encoded = new byte[2 + ipBytes.Length];
                encoded[0] = firstByte;
                encoded[1] = lengthByte;
                Array.Copy(ipBytes, 0, encoded, 2, ipBytes.Length);
                return encoded;
            }
            else
            {
                // For a simple segment, both port and link should be numeric.
                if (!byte.TryParse(LinkValue, out byte linkByte))
                    throw new ArgumentException("For non-extended segment, link must be a numeric value");
                return new byte[] { PortValue, linkByte };
            }
        }
    }

    /// <summary>
    /// Represents a CIP route constructed from a series of port segments.
    /// This class can parse a route specification string (e.g. "2,10.152.35.148")
    /// and generate the proper byte array for the CIP route.
    /// </summary>
    public class CIPRoute
    {
        private readonly List<byte> _segments = new List<byte>();

        /// <summary>
        /// Adds a simple segment (2 bytes) to the route.
        /// </summary>
        public void AddSimpleSegment(byte port, byte link)
        {
            _segments.Add(port);
            _segments.Add(link);
        }

        /// <summary>
        /// Adds an extended segment (IP address) to the route.
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
        /// Combines the route path with an EPath (encrypted request path) to form a complete CIP path.
        /// </summary>
        /// <param name="epath">The encrypted request path bytes.</param>
        /// <returns>A byte array representing the combined CIP path.</returns>
        public byte[] CombineWithEPath(byte[] epath)
        {
            var combined = new List<byte>(_segments);
            combined.AddRange(epath);
            return combined.ToArray();
        }

        /// <summary>
        /// Parses a comma-separated CIP route specification into a CIPRoute.
        /// For example: "2,10.152.35.148" will generate an extended segment if the second token is an IP,
        /// or "1,3" for a simple segment.
        /// </summary>
        /// <param name="routeSpec">The route specification string.</param>
        /// <returns>A CIPRoute object representing the parsed route.</returns>
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
                    if (!byte.TryParse(linkPart, out byte link))
                        throw new ArgumentException($"Invalid segment '{linkPart}'");
                    route.AddSimpleSegment(port, link);
                }
            }

            return route;
        }
    }

    /// <summary>
    /// Provides a method to generate an Encrypted Request Path (EPath) according to
    /// CIP specifications (see Volume 1 Appendix C (C9)).
    /// Example:
    ///   For 8-bit:  20 05 24 02 30 01
    ///   For 16-bit: 21 00 05 00 24 02 30 01
    /// </summary>
    public static class EPath
    {
        /// <summary>
        /// Get the Encrypted Request Path.
        /// </summary>
        /// <param name="classID">Requested Class ID.</param>
        /// <param name="instanceID">Requested Instance ID.</param>
        /// <param name="attributeID">Requested Attribute ID - if "0" the attribute will be ignored.</param>
        /// <returns>Encrypted Request Path as a byte array.</returns>
        public static byte[] GetEPath(int classID, int instanceID, int attributeID)
        {
            int byteCount = 0;
            if (classID < 0xff)
                byteCount += 2;
            else
                byteCount += 4;

            if (instanceID < 0xff)
                byteCount += 2;
            else
                byteCount += 4;

            if (attributeID != 0)
            {
                if (attributeID < 0xff)
                    byteCount += 2;
                else
                    byteCount += 4;
            }

            byte[] returnValue = new byte[byteCount];
            int index = 0;

            // Encode Class ID
            if (classID < 0xff)
            {
                returnValue[index++] = 0x20;
                returnValue[index++] = (byte)classID;
            }
            else
            {
                returnValue[index++] = 0x21;
                returnValue[index++] = 0;                             // Padded Byte
                returnValue[index++] = (byte)classID;                 // LSB
                returnValue[index++] = (byte)(classID >> 8);            // MSB
            }

            // Encode Instance ID
            if (instanceID < 0xff)
            {
                returnValue[index++] = 0x24;
                returnValue[index++] = (byte)instanceID;
            }
            else
            {
                returnValue[index++] = 0x25;
                returnValue[index++] = 0;                                // Padded Byte
                returnValue[index++] = (byte)instanceID;                 // LSB
                returnValue[index++] = (byte)(instanceID >> 8);          // MSB
            }

            // Encode Attribute ID (if not zero)
            if (attributeID != 0)
            {
                if (attributeID < 0xff)
                {
                    returnValue[index++] = 0x30;
                    returnValue[index++] = (byte)attributeID;
                }
                else
                {
                    returnValue[index++] = 0x31;
                    returnValue[index++] = 0;                                 // Padded Byte
                    returnValue[index++] = (byte)attributeID;                 // LSB
                    returnValue[index++] = (byte)(attributeID >> 8);          // MSB
                }
            }

            return returnValue;
        }
    }
}
