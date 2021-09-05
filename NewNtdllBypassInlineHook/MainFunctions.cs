using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static NewNtdllBypassInlineHook.NativeFunctions;
using static NewNtdllBypassInlineHook.NativeStructs;

namespace NewNtdllBypassInlineHook
{
    class MainFunctions
    {
        private static Object Locate_Image_Export_Directory(IntPtr BaseAddress)
        {
            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                BaseAddress,
                typeof(IMAGE_DOS_HEADER));

            IntPtr IMAGE_NT_HEADERS64_address = BaseAddress + IMAGE_DOS_HEADER_instance.e_lfanew;
            IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64_instance = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                IMAGE_NT_HEADERS64_address,
                typeof(IMAGE_NT_HEADERS64));

            IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY_instance = IMAGE_NT_HEADERS64_instance.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            
            IntPtr IMAGE_EXPORT_DIRECTORY_address = (IntPtr)(BaseAddress.ToInt64() + (int)IMAGE_DATA_DIRECTORY_instance.VirtualAddress);
            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                IMAGE_EXPORT_DIRECTORY_address, 
                typeof(IMAGE_EXPORT_DIRECTORY));

            return IMAGE_EXPORT_DIRECTORY_instance;
        }

        public static IntPtr Export_Function_Address(IntPtr BaseAddress, string FunctionName)
        {

            // IntPtr CurrentHandle = Process.GetCurrentProcess().Handle;
            // byte[] SyscallPrologue = new byte[4];
            // byte[] SyscallHead = new byte[4] { 0x4c, 0x8b, 0xd1, 0xb8 };

            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance =
                (IMAGE_EXPORT_DIRECTORY)Locate_Image_Export_Directory(BaseAddress);

            IntPtr RVA_AddressOfFunctions = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfFunctions);
            IntPtr RVA_AddressOfNameOrdinals = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNameOrdinals);
            IntPtr RVA_AddressOfNames = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames);

            UInt32 NumberOfNames = IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames;

            for (int iterate_num = 0; iterate_num < NumberOfNames; iterate_num++)
            {
                UInt32 RVA_AddressOfNames_single = (UInt32)Marshal.ReadInt32(RVA_AddressOfNames, 4 * iterate_num);
                string FuncName_temp = Marshal.PtrToStringAnsi((IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfNames_single));

                if (FuncName_temp.ToLower() == FunctionName.ToLower())
                {
                    UInt16 RVA_AddressOfNameOrdinals_single = (UInt16)Marshal.ReadInt16(RVA_AddressOfNameOrdinals, 2 * iterate_num);
                    UInt32 RVA_AddressOfFunctions_single = (UInt32)Marshal.ReadInt32(RVA_AddressOfFunctions, 4 * RVA_AddressOfNameOrdinals_single);
                    IntPtr REAL_Func_Address = (IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfFunctions_single);
                    IntPtr FunctionAddress = REAL_Func_Address;

                    Console.WriteLine(FuncName_temp + " Address : " + REAL_Func_Address);

                    return FunctionAddress;
                }

            }

            return IntPtr.Zero;


        }
    }
}
