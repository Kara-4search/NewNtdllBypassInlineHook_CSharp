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
        private static Object FindObjectAddress(IntPtr BaseAddress, Object StructObject, IntPtr CurrentHandle)
        {
            IntPtr ObjAllocMemAddr = Marshal.AllocHGlobal(Marshal.SizeOf(StructObject.GetType()));
            RtlZeroMemory(ObjAllocMemAddr, Marshal.SizeOf(StructObject.GetType()));

            uint getsize = 0;
            bool return_status = NtReadVirtualMemory(
                CurrentHandle,
                BaseAddress,
                ObjAllocMemAddr,
                (uint)Marshal.SizeOf(StructObject),
                ref getsize
             );

            StructObject = Marshal.PtrToStructure(ObjAllocMemAddr, StructObject.GetType());
            return StructObject;
        }

        private static Object Locate_Image_Export_Directory(IntPtr BaseAddress, IntPtr CurrentHandle)
        {
            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = new IMAGE_DOS_HEADER();
            IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)FindObjectAddress(
                BaseAddress,
                IMAGE_DOS_HEADER_instance,
                CurrentHandle);

            IntPtr IMAGE_NT_HEADER64_address = (IntPtr)(BaseAddress.ToInt64() + (int)IMAGE_DOS_HEADER_instance.e_lfanew);
            IMAGE_NT_HEADERS64 IMAGE_NT_HEADER64_instance = new IMAGE_NT_HEADERS64();
            IMAGE_NT_HEADER64_instance = (IMAGE_NT_HEADERS64)FindObjectAddress(
                IMAGE_NT_HEADER64_address,
                IMAGE_NT_HEADER64_instance,
                CurrentHandle);

            IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY_instance = IMAGE_NT_HEADER64_instance.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            IntPtr IMAGE_EXPORT_DIRECTORY_address = (IntPtr)(BaseAddress.ToInt64() + (int)IMAGE_DATA_DIRECTORY_instance.VirtualAddress);
            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = new IMAGE_EXPORT_DIRECTORY();
            IMAGE_EXPORT_DIRECTORY_instance = (IMAGE_EXPORT_DIRECTORY)FindObjectAddress(
                IMAGE_EXPORT_DIRECTORY_address,
                IMAGE_EXPORT_DIRECTORY_instance,
                CurrentHandle);

            // Console.WriteLine(IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames);
            // Console.WriteLine(ExportDirectoryRVA_address);
            // Console.WriteLine(IMAGE_NT_HEADER64_instance.Signature);
            // Console.WriteLine(IMAGE_NT_HEADER64_Address);
            // Console.WriteLine(IMAGE_DOS_HEADER_instance.e_lfanew);
            return IMAGE_EXPORT_DIRECTORY_instance;
        }

        public static IntPtr Export_Function_Address(IntPtr BaseAddress, string FunctionName)
        {

            IntPtr CurrentHandle = Process.GetCurrentProcess().Handle;
            // byte[] SyscallPrologue = new byte[4];
            // byte[] SyscallHead = new byte[4] { 0x4c, 0x8b, 0xd1, 0xb8 };

            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance =
                (IMAGE_EXPORT_DIRECTORY)Locate_Image_Export_Directory(BaseAddress, CurrentHandle);

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
