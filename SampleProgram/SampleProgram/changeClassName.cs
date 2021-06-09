using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

/*
 * TEST : Windows10 21H1 (OS Build 19043.985)
 * Net Framework Version 4.7.2
 * ntdll Version : 10.0.19041.964
 * user32 Version : 10.0.19041.906
 */
namespace changeClassName
{
    class ClassName
    {
        public const string checkClassName = "WindowsForms10.Window.8";
        public const string changeClassName = "My Class Name";
        #region Windows APIs & Flags
        [DllImport("kernel32.dll", EntryPoint = "LoadLibrary", CharSet = CharSet.Unicode)]
        private extern static uint LoadLibrary(string librayName);

        [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", CharSet = CharSet.Ansi)]
        private extern static uint GetProcAddress(uint hwnd, string procedureName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(uint lpAddress, uint dwSize, MemoryProtection flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(uint dest, uint src, int size);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemoryByteArray(uint dest, byte[] src, int size);

        [DllImport("kernel32")]
        public static extern uint VirtualAlloc(uint lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        #endregion
        public static void Change()
        {

            if (IntPtr.Size == 8)
            {
                System.Windows.Forms.MessageBox.Show("64-bit is not yet supported.",
                    "information",
                    System.Windows.Forms.MessageBoxButtons.OK,
                    System.Windows.Forms.MessageBoxIcon.Error);
                return;
            }

            uint hNTDLL = LoadLibrary("ntdll");
            uint hUser32 = LoadLibrary("user32");

#if DEBUG
            Debug.WriteLine("ntdll.dll Address : " + hNTDLL.ToString("X2"));
            Debug.WriteLine("user32.dll Address : " + hUser32.ToString("X2"));
#endif

            // hooking function
            uint RegisterClassW = GetProcAddress(hUser32, "RegisterClassW");
            uint CreateWindowExW = GetProcAddress(hUser32, "CreateWindowExW");

            // Functions used in ShellCode
            uint wcsncmp = GetProcAddress(hNTDLL, "wcsncmp");
            uint wcscpy = GetProcAddress(hNTDLL, "wcscpy");


#if DEBUG
            Debug.WriteLine("user32.dll::RegisterClassW Address : " + RegisterClassW.ToString("X2"));
            Debug.WriteLine("user32.dll::CreateWindowExW Address : " + CreateWindowExW.ToString("X2"));
            Debug.WriteLine("ntdll.dll::wcsncmp Address : " + wcsncmp.ToString("X2"));
            Debug.WriteLine("ntdll.dll::wcscpy Address : " + wcscpy.ToString("X2"));
#endif

            // Target api address Protection Change
            uint oldProtect;
            VirtualProtect(RegisterClassW, 6, MemoryProtection.ExecuteReadWrite, out oldProtect);
            VirtualProtect(CreateWindowExW, 6, MemoryProtection.ExecuteReadWrite, out oldProtect);

            // ShellCode Memory
            uint hook_RegisterClassW = VirtualAlloc(0, 1000, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
            uint hook_CreateWindowExW = VirtualAlloc(0, 1000, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);


            // injection jmp code
            byte[] jmpCode = new byte[5];
            jmpCode[0] = 0xE9;
            byte[] a = BitConverter.GetBytes(hook_RegisterClassW - RegisterClassW - 5);
            Buffer.BlockCopy(a, 0, jmpCode, 1, 4);
            MoveMemoryByteArray(RegisterClassW, jmpCode, 5);


            // user32::RegisterClassW Hook Code
            makeCode ShellCode = new makeCode(hook_RegisterClassW, 500);

            // backup register and flag
            ShellCode.addByte(0x60);            // pushad
            ShellCode.addByte(0x9C);            // pushfd

            // get WNDCLASSW->lpszClassName pointer
            ShellCode.addBytes("8B7C24 28");    // mov edi,dword ptr ss:[esp+28]
            ShellCode.addBytes("89F8");         // mov eax,edi 
            ShellCode.addBytes("83C0 24");      // add eax,24
            ShellCode.addBytes("8B00");         // mov eax, dword ptr ds:[eax]

            // Compare existing form ClassName
            // call ntdll.wcsncmp
            ShellCode.add5Byte(0x68, (uint)checkClassName.Length);  // push checkClassName
            uint pos1 = ShellCode.add5Byte(0x68, 0);                // push posString
            ShellCode.addByte(0x50);                                // push eax
            ShellCode.addCall(wcsncmp);                             // call ntdll.wcsncmp
            ShellCode.addBytes("83 C4 0C");                         // add esp, 0xC

            // if thisClassName == orgClassName 
            ShellCode.addBytes("85C0");                             // test teax eax
            uint pos3 = ShellCode.addjnz(0);

            // umm.... re get pointer
            ShellCode.addBytes("8B 7C 24 28");                      // mov edi, dword ptr ss:[esp+0x28]
            ShellCode.addBytes("83 C7 24");                         // add edi, 0x24
            ShellCode.addBytes("8B 3F");                            // mov edi, dword ptr ds:[edi]

            // call ntdll.wcscpy 
            uint p7 = ShellCode.add5Byte(0x68, 0);                  // push string
            ShellCode.addBytes("57");                               // push edi
            ShellCode.addCall(wcscpy);                              // call ntdll.wcscpy
            ShellCode.addBytes("83 C4 08");                         // add esp, 0x8

            // jmp
            uint p4 = ShellCode.addByte(0x9D);                      // popfd
            ShellCode.addByte(0x61);                                // popad

            // run orignal code
            ShellCode.addByte(0x8B);    // mov edi, edi
            ShellCode.addByte(0xFF);
            ShellCode.addByte(0x55);    // push ebp
            ShellCode.addByte(0x8B);    // mov ebp, esp
            ShellCode.addByte(0xEC);

            // jmp user32.RegisterClassW + 5
            ShellCode.addJmp(RegisterClassW + 5);

            // data string
            uint posString = ShellCode.WriteStringUnicode(checkClassName);
            uint posString2 = ShellCode.WriteStringUnicode(changeClassName);
            ShellCode.set5Byte(pos1, 0x68, posString);
            ShellCode.setjnz(pos3, p4 + ShellCode.basdAddress);
            ShellCode.set5Byte(p7, 0x68, posString2);
            MoveMemoryByteArray(hook_RegisterClassW, ShellCode.shellCode, (int)ShellCode.codeSize);




            // injection user32.CreateWindowExW jmp code
            jmpCode[0] = 0xE9;
            a = BitConverter.GetBytes(hook_CreateWindowExW - CreateWindowExW - 5);
            Buffer.BlockCopy(a, 0, jmpCode, 1, 4);
            MoveMemoryByteArray(CreateWindowExW, jmpCode, 5);

            // backup register and flag
            makeCode ShellCode2 = new makeCode(hook_CreateWindowExW, 500);
            ShellCode2.addByte(0x60); // pushad
            ShellCode2.addByte(0x9C); // pushfd

            // get lpClassName address check > 0x400000
            ShellCode2.addBytes("8B4424 2C");           // mov eax,dword ptr ss:[esp+2C]
            ShellCode2.addBytes("3D 00 00 40 00");      // cmp eax, 0x400000
            uint pos3344 = ShellCode2.addjb(0);


            ShellCode2.add5Byte(0x68, (uint)checkClassName.Length);     // push checkClassName
            uint pos11 = ShellCode2.add5Byte(0x68, 0);                  // push posString
            ShellCode2.addByte(0x50);                                   // push eax
            ShellCode2.addCall(wcsncmp);                                // call ntdll.wcscmp 
            ShellCode2.addBytes("83 C4 0C");                            // add esp, 0xC

            ShellCode2.addBytes("85C0");                                // test teax eax
            uint pos33 = ShellCode2.addjnz(0);

            ShellCode2.addBytes("8B 7C 24 2C");                         // mov edi, dword ptr ss:[esp+0x2C]


            uint p77 = ShellCode2.add5Byte(0x68, 0);                    // push string
            ShellCode2.addBytes("57");                                  // push edi
            ShellCode2.addCall(wcscpy);                                 // call ntdll.wcscpy
            ShellCode2.addBytes("83 C4 08");                            // add esp, 0x8


            uint p44 = ShellCode2.addByte(0x9D);    // popfd
            ShellCode2.addByte(0x61);               // popad


            ShellCode2.addByte(0x8B);    // mov edi, edi
            ShellCode2.addByte(0xFF);
            ShellCode2.addByte(0x55);    // push ebp
            ShellCode2.addByte(0x8B);    // mov ebp, esp
            ShellCode2.addByte(0xEC);
            ShellCode2.addJmp(CreateWindowExW + 5);


            ShellCode2.set5Byte(pos11, 0x68, posString);
            ShellCode2.setjnz(pos33, p44 + ShellCode2.basdAddress);
            ShellCode2.setjb(pos3344, p44 + ShellCode2.basdAddress);
            ShellCode2.set5Byte(p77, 0x68, posString2);
            MoveMemoryByteArray(hook_CreateWindowExW, ShellCode2.shellCode, (int)ShellCode2.codeSize);
        }





        class makeCode
        {
            public makeCode(uint baseAddr, uint maxCodeSize)
            {
                shellCode = new byte[maxCodeSize];
                basdAddress = baseAddr;
            }


            public uint addByte(byte b)
            {
                uint org = codeSize;
                shellCode[codeSize] = b;
                codeSize++;
                return org;
            }

            public uint add5Byte(byte opcode, uint operand)
            {
                uint currentPosition = codeSize;

                shellCode[codeSize++] = opcode;
                Buffer.BlockCopy(BitConverter.GetBytes(operand), 0, shellCode, (int)codeSize, 4);

                codeSize += 4;
                return currentPosition;
            }

            public void set5Byte(uint codePosition, byte opcode, uint operand)
            {
                shellCode[codePosition++] = opcode;
                Buffer.BlockCopy(BitConverter.GetBytes(operand), 0, shellCode, (int)codePosition, 4);
            }


            public uint addJmp(uint Address)
            {
                shellCode[codeSize++] = 0xE9;
                Buffer.BlockCopy(BitConverter.GetBytes(Address - (basdAddress + codeSize - 1) - 5), 0, shellCode, (int)codeSize, 4);

                codeSize += 4;
                return codeSize;
            }

            public uint addjnz(uint Address)
            {
                uint org = codeSize;

                shellCode[codeSize++] = 0x0F;
                shellCode[codeSize++] = 0x85;

                Buffer.BlockCopy(BitConverter.GetBytes(Address - (basdAddress + codeSize - 2) - 6), 0, shellCode, (int)codeSize, 4);

                codeSize += 4;
                return org;
            }


            public uint addjb(uint Address)
            {
                uint org = codeSize;

                shellCode[codeSize++] = 0x0F;
                shellCode[codeSize++] = 0x82;

                Buffer.BlockCopy(BitConverter.GetBytes(Address - (basdAddress + codeSize - 2) - 6), 0, shellCode, (int)codeSize, 4);

                codeSize += 4;
                return org;
            }
            public uint setjb(uint codePosition, uint Address)
            {
                uint org = codeSize;
                shellCode[codePosition++] = 0x0F;
                shellCode[codePosition++] = 0x82;
                Buffer.BlockCopy(BitConverter.GetBytes(Address - (basdAddress + codePosition + 4)), 0, shellCode, (int)codePosition, 4);
                return org;
            }


            public uint setjnz(uint codePosition, uint Address)
            {
                uint org = codeSize;
                shellCode[codePosition++] = 0x0F;
                shellCode[codePosition++] = 0x85;
                Buffer.BlockCopy(BitConverter.GetBytes(Address - (basdAddress + codePosition + 4)), 0, shellCode, (int)codePosition, 4);
                return org;
            }


            public uint addBytes(string hexBytes)
            {
                uint org = codeSize;

                hexBytes = hexBytes.Replace(" ", "");

                byte[] convertArr = new byte[hexBytes.Length / 2];

                for (int i = 0; i < convertArr.Length; i++)
                {
                    convertArr[i] = Convert.ToByte(hexBytes.Substring(i * 2, 2), 16);
                }
                Buffer.BlockCopy(convertArr, 0, shellCode, (int)codeSize, convertArr.Length);



                codeSize += (uint)convertArr.Length;
                return org;
            }

            public uint addCall(uint Address)
            {
                shellCode[codeSize++] = 0xE8;
                Buffer.BlockCopy(BitConverter.GetBytes(Address - (basdAddress + codeSize - 1) - 5), 0, shellCode, (int)codeSize, 4);

                codeSize += 4;
                return codeSize;
            }


            public uint WriteStringUnicode(string str)
            {

                byte[] StrByte = Encoding.Unicode.GetBytes(str + "\x00\x00");

                uint stringp = codeSize;

                Buffer.BlockCopy(StrByte, 0, shellCode, (int)codeSize, StrByte.Length);
                codeSize += (uint)StrByte.Length;

                return basdAddress + stringp;
            }



            public byte[] shellCode;
            public uint codeSize;
            public uint basdAddress;
        }
    }
}
