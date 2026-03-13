# x64 PE Code Cave Injector

A python based tool that injects custom commands into windows pe files. It accomplishes this by automatically creating a new PE section, executing a hidden command, and seamlessly returning control to the original program.

⚠️ **Disclaimer:** This tool is created for educational purposes, malware analysis, and authorized red team operations. Do not use this on systems or executables you do not own or have explicit permission to modify.

## Prerequisites

* Python 3.x
* `pefile` library

## Usage

```bash
python main.py <path_to_target_executable.exe>
```

## Debugging

If you want to analyze the injected code cave in a debugger like **x64dbg**, the script prints the virtual address (VA) of the generated cave upon success. 
1. Open `patched.exe` in x64dbg.
2. Press `Ctrl + G` and paste the provided address.
