# Android-File-Transfer-Mac

> A modern, user-friendly desktop file manager for Android devices on macOS

## Why I Built This

I found myself constantly uploading files to cloud storage and then re-downloading them to my Android phone - a process that was both time-consuming and inefficient. Whether it was transferring photos, documents, or large media files, the cloud storage workflow added unnecessary steps and wasted bandwidth.

**With this tool, you can utilize ADB commands through a user-friendly graphical interface, making file transfers between macOS and Android devices seamless and efficient.** No more cloud uploads, no more waiting - just direct, fast file transfers.

## Features

✨ **Easy File Transfers**
- 📤 Upload files and folders from Mac to Android
- 📥 Download files and folders from Android to Mac
- 🚀 Direct transfer via ADB (no cloud required)

📱 **Device Management**
- 🔌 Auto-detect connected Android devices
- 🔄 Support for multiple devices
- 📱 Install APK files directly

📂 **Full File Management**
- 📁 Browse Android file system with intuitive UI
- 🗑️ Delete files and folders
- 🔍 Navigate through directories easily
- 📊 View file sizes and permissions

💻 **User Interface**
- 🎨 Clean, modern PyQt6 interface
- ⚡ Fast and responsive
- 🖱️ Right-click context menus

## Screenshots

<img width="1209" height="833" alt="image" src="https://github.com/user-attachments/assets/8f224e6d-faf8-44e9-8c5c-1e97b5c58cf7" />


## Requirements

- **macOS** (tested on macOS 10.15+)
- **Python 3.8+**
- **ADB (Android Debug Bridge)** - Install via:
  ```bash
  brew install android-platform-tools
  ```
- **Android device** with USB debugging enabled

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/adb-file-manager-macos.git
cd adb-file-manager-macos
```

### 2. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Enable USB Debugging on your Android device
1. Go to **Settings** → **About Phone**
2. Tap **Build Number** 7 times to enable Developer Options
3. Go to **Settings** → **Developer Options**
4. Enable **USB Debugging**

### 5. Connect your device and verify ADB
```bash
adb devices
```

You should see your device listed. If prompted on your phone, allow USB debugging.

## Usage

### Run the PyQt6 version (Recommended)
```bash
python android_file_manager_pyqt6.py
```

### Basic Operations

1. **Connect Device**: Select your device from the dropdown
2. **Browse Files**: Double-click folders to navigate
3. **Upload Files**: Click "Upload File" or "Upload Folder" button
4. **Download Files**: Right-click on any file/folder and select "Download"
5. **Delete Files**: Right-click and select "Delete"
6. **Install APK**: Click "Install APK" button and select an APK file

## How It Works

This application uses ADB (Android Debug Bridge) commands under the hood, but wraps them in an intuitive graphical interface. No need to remember complex command-line syntax - just click and drag!

**Key technologies:**
- **PyQt6**: Modern Python GUI framework
- **ADB**: Android Debug Bridge for device communication
- **Python subprocess**: Execute ADB commands

## File Transfer Speed

Transfer speeds depend on:
- USB connection type (USB 2.0 vs USB 3.0)
- Cable quality
- File size and type

Typical speeds: **10-40 MB/s** via USB 3.0

## Common Issues & Solutions

### Device not showing up?
- Ensure USB debugging is enabled
- Try a different USB cable
- Run `adb kill-server` and `adb start-server`
- Check that ADB is installed: `adb --version`

### Permission denied errors?
- Grant file access permissions on your Android device
- Some system folders require root access

### "Command not found" error?
- Install ADB: `brew install android-platform-tools`
- Make sure ADB is in your PATH

## Project Structure

```
adb-filemanager/
├── android_file_manager_pyqt6.py  # Main PyQt6 application
├── requirements.txt                # Python dependencies
├── README.md                       # This file
└── .gitignore                      # Git ignore rules
```

## Dependencies

- **PyQt6** - Modern Qt bindings for Python

See `requirements.txt` for complete list.

## Contributing

Contributions are welcome! Feel free to:
- 🐛 Report bugs
- 💡 Suggest new features
- 🔧 Submit pull requests
- 📖 Improve documentation

## License

MIT License - feel free to use this project for personal or commercial purposes.

## Acknowledgments

Built with ❤️ to solve a real problem: making Android file transfers on macOS painless and efficient.

## Support

If you find this tool useful, please ⭐ star this repository!

For issues or questions, please [open an issue](https://github.com/yourusername/adb-file-manager-macos/issues).

---

**Keywords**: Android file manager, macOS, ADB, file transfer, Android to Mac, USB file transfer, Android file browser, ADB GUI, Android file explorer, Mac Android manager
