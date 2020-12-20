using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace UNBURST
{
    /// <summary>
    /// Courtesy https://securityboulevard.com/2020/12/reassembling-victim-domain-fragments-from-sunburst-dns/
    /// by Erik Hjelmvik on December 17, 2020
    /// </summary>
    class SunburstDomainDecoder
    {
        /// <summary>
        /// OrionImprovementBusinessLayer.ZipHelper.Unzip("Kyo0Ti9OzCkxKzXMrEyryi8wNTdKMbFMyquwSC7LzU4tz8gCAA==");
        /// </summary>
        private const string SUBSTITUTION_CIPHER_ALPHABET = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj";
        private readonly Dictionary<char, char> reverseSubstitutionCipherDictionary;

        /// <summary>
        /// OrionImprovementBusinessLayer.ZipHelper.Unzip("M4jX1QMA");
        /// </summary>
        private const string SPECIAL_CHARS = "0_-.";

        /// <summary>
        /// OrionImprovementBusinessLayer.ZipHelper.Unzip("K8gwSs1MyzfOMy0tSTfMskixNCksKkvKzTYoTswxN0sGAA==");
        /// </summary>
        private const string BASE32_ALPHABET = "ph2eifo3n5utg1j8d94qrvbmk0sal76c";
        private readonly Dictionary<char, uint> reverseBase32Dictionary;


        public static List<string> Decode(string[] fqdns)
        {
            List<string> ret = new List<string>();
            SunburstDomainDecoder decoder = new SunburstDomainDecoder();
            try
            {
                ret = decoder.ExtractEncodedDomains(fqdns);
            }

            catch { }
            return ret;
        }

        public SunburstDomainDecoder()
        {
            //preparde dictionaries for faster lookups (Array.IndexOf is slow)
            this.reverseSubstitutionCipherDictionary = new Dictionary<char, char>(SUBSTITUTION_CIPHER_ALPHABET.Length);
            foreach (char encoded in SUBSTITUTION_CIPHER_ALPHABET)
            {
                this.reverseSubstitutionCipherDictionary.Add(encoded, this.ReverseSubstituteChar(encoded));
            }
            this.reverseBase32Dictionary = new Dictionary<char, uint>(BASE32_ALPHABET.Length);
            foreach (char encoded in BASE32_ALPHABET)
            {
                this.reverseBase32Dictionary.Add(encoded, (uint)BASE32_ALPHABET.IndexOf(encoded));
            }
        }

        private char ReverseSubstituteChar(char c)
        {
            int index = SUBSTITUTION_CIPHER_ALPHABET.IndexOf(c) - 4;
            return SUBSTITUTION_CIPHER_ALPHABET[(index + SUBSTITUTION_CIPHER_ALPHABET.Length) % SUBSTITUTION_CIPHER_ALPHABET.Length];
        }

        private List<string> ExtractEncodedDomains(IEnumerable<string> queriedDomains)
        {
            List<string> ret = new List<string>();
            IDictionary<string, List<string>> guidDomainDictionary = new SortedDictionary<string, List<string>>();
            Dictionary<string, string> base32EncodedSegments = new Dictionary<string, string>();
            Dictionary<string, string> substitutionCipherSegments = new Dictionary<string, string>();
            foreach (string queriedDomain in queriedDomains.Where((s) => s.Length > 16))
            {
                try
                {
                    string subdomain = queriedDomain.Split('.').First();
                    if (subdomain.Length > 16)
                    {
                        string secureString = subdomain.Substring(0, 15);
                        byte[] guidBytes = new byte[8];
                        Array.Copy(this.DecryptSecureString(secureString), 0, guidBytes, 0, 8);
                        string guidString = BitConverter.ToString(guidBytes).Replace("-", string.Empty);
                        string encodedDomain = subdomain.Substring(16);
                        string decodedDomain;
                        if (encodedDomain.StartsWith("00"))
                        {
                            decodedDomain = UTF8Encoding.UTF8.GetString(this.Base32DecodeBinary(encodedDomain.Substring(2)).ToArray());
                            if (!base32EncodedSegments.ContainsKey(guidString))
                            {
                                base32EncodedSegments.Add(guidString, encodedDomain.Substring(2));
                                if (substitutionCipherSegments.ContainsKey(guidString))
                                {
                                    if (this.TryGetMergedBase32Domain(new[] { encodedDomain.Substring(2), substitutionCipherSegments[guidString] }, out string mergedDomain))
                                    {
                                        string previousDomain = mergedDomain.Substring(decodedDomain.Length);
                                        if (guidDomainDictionary.ContainsKey(guidString))
                                        {
                                            var l = guidDomainDictionary[guidString];
                                            l[l.Count - 1] = previousDomain;
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            decodedDomain = this.DecodeDomainString(encodedDomain);
                            if (base32EncodedSegments.ContainsKey(guidString))
                            {
                                string firstSegment = base32EncodedSegments[guidString];

                                if (this.TryGetMergedBase32Domain(new[] { firstSegment, encodedDomain }, out string mergedDomain))
                                {
                                    decodedDomain = mergedDomain.Substring(UTF8Encoding.UTF8.GetString(this.Base32DecodeBinary(firstSegment).ToArray()).Length);
                                    base32EncodedSegments[guidString] = mergedDomain;
                                }
                            }
                            else if (!substitutionCipherSegments.ContainsKey(guidString))
                                substitutionCipherSegments.Add(guidString, encodedDomain);
                        }

                        ret.Add(guidString + " " + decodedDomain + " " + subdomain);
                        List<string> domainSegments;
                        if (guidDomainDictionary.ContainsKey(guidString))
                        {
                            domainSegments = guidDomainDictionary[guidString];
                            if (domainSegments.Contains(decodedDomain))
                                continue;
                        }
                        else
                        {
                            domainSegments = new List<string>() { string.Empty };//separator between last segment and other segments
                            guidDomainDictionary.Add(guidString, domainSegments);
                        }
                        if (this.IsLastDomainSegment(subdomain[15], subdomain[0]))
                            domainSegments.Add(decodedDomain);
                        else
                            domainSegments.Insert(0, decodedDomain);
                    }
                }
                catch { }
            }

            //foreach (var guidAndDomain in guidDomainDictionary)
            //{
            //    if (guidAndDomain.Value.Last() != string.Empty)//only print domains that we have the last segment for
            //        Console.WriteLine(string.Join("\t", guidAndDomain.Key, string.Join("", guidAndDomain.Value)));
            //}
            return ret;
        }

        private bool TryGetMergedBase32Domain(IEnumerable<string> base32EncodedSegments, out string mergedDomain)
        {
            mergedDomain = UTF8Encoding.UTF8.GetString(this.Base32DecodeBinary(string.Join("", base32EncodedSegments)).ToArray());
            return mergedDomain.All((c) => this.reverseSubstitutionCipherDictionary.ContainsKey(char.ToLower(c)) || SPECIAL_CHARS.Contains(c));
        }

        //Inverted OrionImprovementBusinessLayer.CryptoHelper.CreateString(int n, char c)
        private bool IsLastDomainSegment(char c, char firstChar)
        {
            if (c == (35 + firstChar) % 36 + 48)
                return true;
            else if (c == (35 + firstChar) % 36 + 87)
                return true;
            else
                return false;
        }

        //Inverted OrionImprovementBusinessLayer.CryptoHelper.Base64Decode(string s)
        private string DecodeDomainString(string encodedDomain)
        {
            StringBuilder decodedDomain = new StringBuilder();
            bool nextCharIsSpecial = false;
            foreach (char c in encodedDomain)
            {
                if (nextCharIsSpecial)
                {
                    int index = SUBSTITUTION_CIPHER_ALPHABET.IndexOf(c);
                    decodedDomain.Append(SPECIAL_CHARS[(index + SPECIAL_CHARS.Length) % SPECIAL_CHARS.Length]);
                    nextCharIsSpecial = false;
                }
                else if (SPECIAL_CHARS.Contains(c))
                {
                    nextCharIsSpecial = true;
                }
                else if (this.reverseSubstitutionCipherDictionary.ContainsKey(c))
                    decodedDomain.Append(this.reverseSubstitutionCipherDictionary[c]);
                else
                {//backup for unexpected input
                    decodedDomain.Append(this.ReverseSubstituteChar(c));
                }
            }
            return decodedDomain.ToString();
        }

        //Inverted OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString(byte[] data, bool flag)
        private byte[] DecryptSecureString(string secureString)
        {
            byte[] decodedBytes = this.Base32DecodeBinary(secureString).ToArray();
            byte[] decryptedBytes = new byte[decodedBytes.Length - 1];
            byte xorKey = decodedBytes[0];
            for (int i = 0; i < decryptedBytes.Length; i++)
                decryptedBytes[i] = (byte)(decodedBytes[i + 1] ^ xorKey);
            return decryptedBytes;
        }

        //Inverted OrionImprovementBusinessLayer.CryptoHelper.Base64Encode(byte[] bytes, bool rt)
        private IEnumerable<byte> Base32DecodeBinary(string encodedBinary)
        {
            if (!encodedBinary.All((char c) => this.reverseBase32Dictionary.Keys.Contains(c)))
            {
                encodedBinary = string.Concat(encodedBinary.Where((char c) => this.reverseBase32Dictionary.Keys.Contains(c)));
            }
            uint buffer = 0u;
            int bitCount = 0;
            foreach (char c in encodedBinary)
            {
                buffer |= (this.reverseBase32Dictionary[c] << bitCount);
                bitCount += 5;
                if (bitCount > 7)
                {
                    yield return (byte)buffer;
                    buffer >>= 8;
                    bitCount -= 8;
                }
            }
        }
    }
}
