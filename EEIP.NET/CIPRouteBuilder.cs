using System;
using System.Collections.Generic;
using System.Text;
/// <summary>
/// Provides a method to parse a CIP path string (such as "0,1,192.168.2.1,0,1")
/// into the proper byte sequence.
/// 
/// The algorithm:
/// 1. Removes spaces and square brackets.
/// 2. Splits the path on commas.
/// 3. For each token:
///    - If it contains a dot ('.'), it’s assumed to be an IP address (or symbolic address).
///      In this case, the parser sets bit 5 (i.e. OR with 1<<4) in the previous byte,
///      then appends a length byte followed by the ASCII bytes of the token.
///    - Otherwise, it converts the token to a number (0–255) and appends it as a single byte.
/// </summary>
namespace Sres.Net.EEIP
{
    public static class CIPRouteBuilder
    {
        /// <summary>
        /// Parses a CIP path string (e.g. "0,1,192.168.2.1,0,1") and returns the equivalent byte array.
        /// The algorithm:
        /// 1. Removes spaces and square brackets.
        /// 2. Splits the path on commas.
        /// 3. For each token:
        ///    - If the token contains a dot, it is assumed to be an IP (or symbolic) address.
        ///      In that case, the parser sets bit 5 (i.e. OR with 1<<4) in the previous byte,
        ///      then appends a length byte followed by the ASCII bytes of the token.
        ///    - Otherwise, it converts the token to a number (0–255) and appends it as a single byte.
        /// </summary>
        /// <param name="path">The CIP path string.</param>
        /// <returns>A byte array representing the parsed CIP path.</returns>
        /// <exception cref="ArgumentException">Thrown if an IP address segment is the first element.</exception>
        /// <exception cref="FormatException">Thrown when conversion to a number fails.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when a numeric value is not in the 0–255 range.</exception>
        public static byte[] ParsePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Invalid path: empty or null.");
            }

            // Remove spaces and square brackets.
            path = path.Replace(" ", "").Replace("[", "").Replace("]", "");
            // Split on commas.
            string[] parts = path.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            List<byte> bytePath = new List<byte>(parts.Length);

            foreach (string part in parts)
            {
                // Check if the token looks like an IP address or symbolic string.
                if (part.Contains("."))
                {
                    // Ensure that there is a preceding segment to modify.
                    if (bytePath.Count == 0)
                    {
                        throw new ArgumentException("Invalid path: an IP address segment cannot be the first element.");
                    }
                    // Set bit 5 (i.e. 1<<4) in the previous byte.
                    int lastIndex = bytePath.Count - 1;
                    bytePath[lastIndex] = (byte)(bytePath[lastIndex] | (1 << 4));

                    // Append a byte for the length of the ASCII string.
                    byte lenByte = (byte)part.Length;
                    bytePath.Add(lenByte);

                    // Append the ASCII bytes for the string.
                    byte[] asciiBytes = Encoding.ASCII.GetBytes(part);
                    bytePath.AddRange(asciiBytes);
                }
                else
                {
                    // Convert the numeric token.
                    if (!int.TryParse(part, out int value))
                    {
                        throw new FormatException($"Problem converting \"{part}\" to a number.");
                    }
                    if (value < 0 || value > 255)
                    {
                        throw new ArgumentOutOfRangeException(nameof(part), $"Number out of range: {part}");
                    }
                    bytePath.Add((byte)value);
                }
            }

            if (bytePath.Count % 2 != 0)
            {
                bytePath.Add(0);
            }

            return bytePath.ToArray();
        }
    }   
}