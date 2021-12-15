from capstone import *
import sys
import re

hashes = [(0x006B8029, 'ws2_32.dll!WSAStartup'),
              (0xE0DF0FEA, 'ws2_32.dll!WSASocketA'),
              (0x6737DBC2, 'ws2_32.dll!bind'),
              (0xFF38E9B7, 'ws2_32.dll!listen'),
              (0xE13BEC74, 'ws2_32.dll!accept'),
              (0x614D6E75, 'ws2_32.dll!closesocket'),
              (0x6174A599, 'ws2_32.dll!connect'),
              (0x5FC8D902, 'ws2_32.dll!recv'),
              (0x5F38EBC2, 'ws2_32.dll!send'),

              (0x5BAE572D, 'kernel32.dll!WriteFile'),
              (0x4FDAF6DA, 'kernel32.dll!CreateFileA'),
              (0x13DD2ED7, 'kernel32.dll!DeleteFileA'),
              (0xE449F330, 'kernel32.dll!GetTempPathA'),
              (0x528796C6, 'kernel32.dll!CloseHandle'),
              (0x863FCC79, 'kernel32.dll!CreateProcessA'),
              (0xE553A458, 'kernel32.dll!VirtualAlloc'),
              (0x300F2F0B, 'kernel32.dll!VirtualFree'),
              (0x0726774C, 'kernel32.dll!LoadLibraryA'),
              (0x7802F749, 'kernel32.dll!GetProcAddress'),
              (0x601D8708, 'kernel32.dll!WaitForSingleObject'),
              (0x876F8B31, 'kernel32.dll!WinExec'),
              (0x9DBD95A6, 'kernel32.dll!GetVersion'),
              (0xEA320EFE, 'kernel32.dll!SetUnhandledExceptionFilter'),
              (0x56A2B5F0, 'kernel32.dll!ExitProcess'),
              (0x0A2A1DE0, 'kernel32.dll!ExitThread'),

              (0x6F721347, 'ntdll.dll!RtlExitUserThread'),

              (0x23E38427, 'advapi32.dll!RevertToSelf')
              ]

def find_api(addr):
	result = f''
	for index, tuple in enumerate(hashes):
		apihash = tuple[0]
		apiname = tuple[1]
		addr_int = int(addr, base=16)
		if addr_int == apihash:
			result = f'{addr} ({apiname})'
			return result
	return result
			  
if __name__ == '__main__':
	
	with open(sys.argv[1], "rb") as f:
		CODE = f.read()

	regex = '^0x([0-9]|[A-Z]|[a-z]){7,}'
	pattern = re.compile(regex)

	md = md = Cs(CS_ARCH_X86, CS_MODE_32)
	for i in md.disasm(CODE, 0x1000):
		format_string = "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
		args = i.op_str.split()
		for a in args:
			if pattern.match(a):
				api = find_api(a)
				if api:
					format_string = "0x%x:\t%s\t%s //%s" %(i.address, i.mnemonic, i.op_str, api)
		print(format_string)