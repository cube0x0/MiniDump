using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Minidump;
using Minidump.Streams;

namespace Minidump.Templates
{
    public class lsaTemplate_NT5
    {
        public struct LsaTemplate_NT5
        {
            public byte[] signature;
            public uint feedback;
            public uint randomkey_ptr;
            public uint DESXKey_ptr;
            public uint key_struct;
            public string nt_major;
        }

        public static void get_template(SystemInfo.MINIDUMP_SYSTEM_INFO sysinfo)
        {
            var template = new LsaTemplate_NT5();
            template.nt_major = "6";

            if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.INTEL)
            {
                if (sysinfo.BuildNumber <= (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    return Templates["nt5"]["x86"]["1"];
                }
                else
                {
                    throw new Exception("NT 6 is in another castle!");
                }
            }
            else if (sysinfo.ProcessorArchitecture == SystemInfo.PROCESSOR_ARCHITECTURE.AMD64)
            {
                if (sysinfo.BuildNumber <= (int)SystemInfo.WindowsMinBuild.WIN_VISTA)
                {
                    return Templates["nt5"]["x64"]["1"];
                }
                else
                {
                    throw new Exception("NT 6 is in another castle!");
                }
            }
        }
    }

    public class SYMCRYPT_NT5_DES_EXPANDED_KEY
    {
        public List<object> roundKey;

        public SYMCRYPT_NT5_DES_EXPANDED_KEY(object reader)
        {
            roundKey = new List<object>();
            foreach (var _ in Enumerable.Range(0, 16))
            {
                var r = Helpers.ReadUInt16(fileBinaryReader);
                var l = Helpers.ReadUInt16(fileBinaryReader);
                roundKey.Add(new List<object>
                {
                    r,
                    l
                });
            }
        }
    }

    public class SYMCRYPT_NT5_DESX_EXPANDED_KEY
    {
        public SYMCRYPT_NT5_DES_EXPANDED_KEY desKey;

        public object inputWhitening;

        public object outputWhitening;

        public SYMCRYPT_NT5_DESX_EXPANDED_KEY(object reader)
        {
            inputWhitening = reader.read(8);
            outputWhitening = reader.read(8);
            desKey = new SYMCRYPT_NT5_DES_EXPANDED_KEY(reader);
        }
    }

    public class PSYMCRYPT_NT5_DESX_EXPANDED_KEY
    {
        public PSYMCRYPT_NT5_DESX_EXPANDED_KEY(object reader)
            : base(SYMCRYPT_NT5_DESX_EXPANDED_KEY)
        {
        }
    }

    public class LSA_x64_nt5_1
    {
        public string arch;

        public int desx_key_ptr_offset;

        public int feedback_ptr_offset;

        public PSYMCRYPT_NT5_DESX_EXPANDED_KEY key_struct_ptr;

        public string nt_major;

        public int old_feedback_offset;

        public int randomkey_ptr_offset;

        public string signature;

        public LSA_x64_nt5_1()
        {
            arch = "x64";
            signature = new byte[] {0x33, 0xdb, 0x8b, 0xc3, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3};
            nt_major = "5";
            feedback_ptr_offset = -67;
            randomkey_ptr_offset = -17;
            desx_key_ptr_offset = -35;
            old_feedback_offset = 29;
            key_struct_ptr = PSYMCRYPT_NT5_DESX_EXPANDED_KEY;
        }
    }

    public class LSA_x86_nt5_1
    {
        public string arch;

        public int desx_key_ptr_offset;

        public int feedback_ptr_offset;

        public PSYMCRYPT_NT5_DESX_EXPANDED_KEY key_struct_ptr;

        public string nt_major;

        public int old_feedback_offset;

        public int randomkey_ptr_offset;

        public string signature;

        public LSA_x86_nt5_1()
        {
            arch = "x86";
            nt_major = "5";
            signature = new byte[] {0x05, 0x90, 0x00, 0x00, 0x00, 0x6a, 0x18, 0x50, 0xa3};
            feedback_ptr_offset = 25;
            randomkey_ptr_offset = 9;
            desx_key_ptr_offset = -4;
            old_feedback_offset = 29;
            key_struct_ptr = PSYMCRYPT_NT5_DESX_EXPANDED_KEY;
        }
    }

}