import sys
import subprocess
import os
import json
import logging
import shlex
from pathlib import Path, PurePosixPath
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QLineEdit, QTreeWidget, QTreeWidgetItem,
    QFileDialog, QMessageBox, QProgressDialog, QHeaderView, QMenu, QTabWidget,
    QTableWidget, QTableWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction


class AndroidFileManager:
    def __init__(self):
        self.current_path = "/storage/emulated/0"
        self.device_id = None
        self.local_path = str(Path.home() / "Downloads")

        # Setup logging
        log_dir = Path.home() / ".android_file_manager"
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "android_fm.log"

        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Android File Manager initialized")

        # Setup backup directory
        self.backup_base_dir = Path(__file__).parent / "storage" / "data" / "backups"
        self.backup_base_dir.mkdir(parents=True, exist_ok=True)
        
    def ensure_device_connected(self):
        """Ensure a device is connected before performing operations

        Returns:
            tuple: (is_connected, error_message)
        """
        if not self.device_id:
            self.logger.warning("No device selected")
            return False, "No device selected. Please connect to a device first."

        # Check if device is still in connected devices list
        connected_devices = self.get_connected_devices()
        if self.device_id not in connected_devices:
            self.logger.error(f"Device {self.device_id} is no longer connected")
            return False, f"Device {self.device_id} is no longer connected. Please reconnect."

        return True, None

    def is_safe_path(self, path):
        """Validate that the path is within allowed Android directories

        Args:
            path: The Android path to validate

        Returns:
            tuple: (is_valid, error_message)
        """
        # Whitelist of safe base paths on Android
        safe_bases = [
            '/storage/emulated/0',
            '/sdcard',
            '/mnt/sdcard',
            '/storage/self/primary',
        ]

        # Normalize the path
        normalized_path = path.strip()

        # Check if path starts with any safe base
        is_safe = any(normalized_path.startswith(base) for base in safe_bases)

        if not is_safe:
            return False, f"Access denied: Path '{path}' is outside allowed directories. Only /sdcard and /storage/emulated/0 are accessible."

        # Additional checks for suspicious patterns
        if '..' in normalized_path:
            return False, "Access denied: Path traversal attempts (..) are not allowed."

        return True, None

    def run_adb_command(self, command, timeout=30, shell=False):
        """Execute ADB command and return output

        Args:
            command: Either a list of command arguments (preferred) or a string command
            timeout: Timeout in seconds
            shell: Whether to use shell=True (avoid when possible for security)
        """
        try:
            # If command is a string and shell is False, this is an error
            if isinstance(command, str) and not shell:
                error_msg = "String commands require shell=True. Use list commands with shell=False instead."
                self.logger.error(error_msg)
                raise ValueError(error_msg)

            self.logger.debug(f"Running ADB command: {command}")

            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                self.logger.warning(f"ADB command failed with code {result.returncode}: {result.stderr}")

            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout} seconds"
            self.logger.error(f"ADB command timeout: {command}")
            return None, error_msg, 1
        except Exception as e:
            self.logger.error(f"ADB command exception: {str(e)}")
            return None, str(e), 1
    
    def check_adb_available(self):
        """Check if ADB is available in PATH

        Returns:
            tuple: (is_available, error_message)
        """
        try:
            result = subprocess.run(
                ["adb", "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self.logger.info(f"ADB is available: {result.stdout.strip().split()[0]}")
                return True, None
            else:
                error_msg = "ADB command failed. Please ensure ADB is properly installed."
                self.logger.error(error_msg)
                return False, error_msg
        except FileNotFoundError:
            error_msg = "ADB not found in PATH. Please install Android SDK Platform Tools and add ADB to your system PATH."
            self.logger.error(error_msg)
            return False, error_msg
        except subprocess.TimeoutExpired:
            error_msg = "ADB command timed out. There may be an issue with your ADB installation."
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error checking ADB availability: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

    def get_connected_devices(self):
        """Get list of connected Android devices"""
        stdout, _stderr, code = self.run_adb_command(["adb", "devices"])
        if code == 0 and stdout:
            lines = stdout.strip().split('\n')[1:]  # Skip header
            devices = []
            for line in lines:
                if '\tdevice' in line:
                    device_id = line.split('\t')[0]
                    devices.append(device_id)
            return devices
        return []
    
    def list_directory(self, path):
        """List contents of Android directory"""
        # Ensure device is connected
        is_connected, error_msg = self.ensure_device_connected()
        if not is_connected:
            return None, error_msg

        # Validate path to prevent directory traversal
        is_valid, error_msg = self.is_safe_path(path)
        if not is_valid:
            return None, error_msg

        # Use command array to prevent shell injection
        # Quote the path to handle spaces and special characters
        quoted_path = shlex.quote(path)
        stdout, stderr, code = self.run_adb_command(["adb", "shell", f"ls -la {quoted_path}"])
        
        if code != 0:
            return None, stderr
        
        files = []
        for line in stdout.strip().split('\n'):
            if not line or line.startswith('total'):
                continue
            
            parts = line.split()
            if len(parts) < 8:
                continue
            
            permissions = parts[0]
            size = parts[4] if len(parts) > 4 else "0"
            name = ' '.join(parts[7:])
            
            if name in ['.', '..']:
                continue
            
            is_dir = permissions.startswith('d')

            # Use PurePosixPath for Android path construction
            file_path = str(PurePosixPath(path) / name)

            files.append({
                'name': name,
                'is_dir': is_dir,
                'size': size,
                'permissions': permissions,
                'path': file_path
            })
        
        return files, None
    
    def pull_file(self, android_path, local_path, is_dir=False):
        """Pull file or directory from Android to local machine"""
        # Ensure device is connected
        is_connected, error_msg = self.ensure_device_connected()
        if not is_connected:
            return False, error_msg

        # Validate Android path to prevent directory traversal
        is_valid, error_msg = self.is_safe_path(android_path)
        if not is_valid:
            return False, error_msg

        # Use command array to prevent shell injection
        if is_dir:
            cmd = ["adb", "pull", "-a", android_path, local_path]
        else:
            cmd = ["adb", "pull", android_path, local_path]
        # Use 10 minute timeout for file transfers (can be large files/OBB)
        stdout, stderr, code = self.run_adb_command(cmd, timeout=600)
        return code == 0, stderr if code != 0 else stdout
    
    def push_file(self, local_path, android_path, is_dir=False):
        """Push file or directory from local machine to Android"""
        # Ensure device is connected
        is_connected, error_msg = self.ensure_device_connected()
        if not is_connected:
            return False, error_msg

        # Validate Android path to prevent directory traversal
        is_valid, error_msg = self.is_safe_path(android_path)
        if not is_valid:
            return False, error_msg

        # Use command array to prevent shell injection
        cmd = ["adb", "push", local_path, android_path]
        # Use 10 minute timeout for file transfers (can be large files/OBB)
        stdout, stderr, code = self.run_adb_command(cmd, timeout=600)
        return code == 0, stderr if code != 0 else stdout
    
    def delete_file(self, android_path):
        """Delete file or directory on Android"""
        # Ensure device is connected
        is_connected, error_msg = self.ensure_device_connected()
        if not is_connected:
            return False, error_msg

        # Validate Android path to prevent directory traversal
        is_valid, error_msg = self.is_safe_path(android_path)
        if not is_valid:
            return False, error_msg

        # Use command array to prevent shell injection
        # Quote the path to handle spaces and special characters
        quoted_path = shlex.quote(android_path)
        stdout, stderr, code = self.run_adb_command(["adb", "shell", f"rm -rf {quoted_path}"])
        return code == 0, stderr if code != 0 else stdout
    
    def install_apk(self, apk_path):
        """Install APK file"""
        # Use command array to prevent shell injection
        cmd = ["adb", "install", apk_path]
        # Use 5 minute timeout for APK installation
        stdout, stderr, code = self.run_adb_command(cmd, timeout=300)
        # Handle None values from timeout/error
        message = (stdout or "") + (stderr or "")
        return code == 0, message

    def install_multiple_apk(self, apk_paths):
        """Install multiple APK files (for split APKs)"""
        # Use command array to prevent shell injection
        cmd = ["adb", "install-multiple"] + [str(path) for path in apk_paths]
        # Use 5 minute timeout for APK installation
        stdout, stderr, code = self.run_adb_command(cmd, timeout=300)
        # Handle None values from timeout/error
        message = (stdout or "") + (stderr or "")
        return code == 0, message

    def list_installed_packages(self):
        """Get list of user-installed packages"""
        # Use command array to prevent shell injection
        stdout, stderr, code = self.run_adb_command(["adb", "shell", "pm", "list", "packages", "-3"])

        if code != 0:
            return None, stderr

        packages = []
        for line in stdout.strip().split('\n'):
            if line.startswith('package:'):
                package_name = line.replace('package:', '').strip()
                packages.append(package_name)

        return packages, None

    def get_package_info(self, package_name):
        """Get detailed information about a package"""
        # Get package path(s) - can be multiple for split APKs
        # Use command array to prevent shell injection
        stdout, stderr, code = self.run_adb_command(["adb", "shell", "pm", "path", package_name])

        if code != 0:
            return None, stderr

        # Parse APK paths - each line starts with "package:"
        apk_paths = []
        # Use splitlines() instead of split('\n') to handle all line ending types
        for line in stdout.strip().splitlines():
            line = line.strip()  # Remove any leading/trailing whitespace including \r
            if line.startswith('package:'):
                apk_path = line.replace('package:', '').strip()
                # Only add non-empty paths
                if apk_path:
                    apk_paths.append(apk_path)

        if not apk_paths:
            return None, "No APK paths found"

        # Debug: Print parsed APK paths
        print(f"DEBUG: Found {len(apk_paths)} APK path(s) for {package_name}:")
        for i, path in enumerate(apk_paths):
            print(f"  [{i}] {repr(path)}")

        # Get package dump info for version and app name
        # Use command array to prevent shell injection
        stdout, stderr, code = self.run_adb_command(["adb", "shell", "dumpsys", "package", package_name])

        version_name = "Unknown"
        version_code = "Unknown"

        if code == 0:
            for line in stdout.split('\n'):
                if 'versionName=' in line:
                    version_name = line.split('versionName=')[1].strip().split()[0]
                elif 'versionCode=' in line:
                    version_code = line.split('versionCode=')[1].strip().split()[0]

        return {
            'package_name': package_name,
            'apk_paths': apk_paths,
            'is_split': len(apk_paths) > 1,
            'version_name': version_name,
            'version_code': version_code
        }, None

    def backup_apk(self, package_name, package_info):
        """Backup APK file(s) from device - handles split APKs"""
        backup_dir = self.backup_base_dir / package_name
        backup_dir.mkdir(parents=True, exist_ok=True)

        apk_paths = package_info['apk_paths']
        backed_up_files = []

        # Validate APK paths first
        for apk_path in apk_paths:
            # Check for newlines or other problematic characters in path
            if '\n' in apk_path or '\r' in apk_path:
                return False, f"Invalid APK path contains newline characters: {repr(apk_path)}", None

            # Verify the file exists on device
            # test -f returns 0 if file exists, non-zero otherwise
            quoted_apk_path = shlex.quote(apk_path)
            check_cmd = ["adb", "shell", f"test -f {quoted_apk_path}"]
            _stdout, _stderr, code = self.run_adb_command(check_cmd)
            if code != 0:
                return False, f"APK file does not exist on device: {apk_path}", None

        # Pull each APK file
        for apk_path in apk_paths:
            # Get filename from path
            filename = os.path.basename(apk_path)

            # For single APK, use package name; for split APKs, preserve original names
            if len(apk_paths) == 1:
                dest_filename = f"{package_name}.apk"
            else:
                dest_filename = filename

            apk_dest = backup_dir / dest_filename

            # Pull APK
            success, message = self.pull_file(apk_path, str(apk_dest), False)

            if not success:
                return False, f"Failed to pull {filename}: {message}", None

            backed_up_files.append(str(apk_dest))

        return True, f"Backed up {len(backed_up_files)} APK file(s)", str(backup_dir)

    def backup_obb(self, package_name):
        """Backup OBB files if they exist"""
        # Use PurePosixPath for Android path construction
        obb_android_path = str(PurePosixPath("/sdcard/Android/obb") / package_name)

        # Check if OBB directory exists using test -d
        # test -d returns 0 if directory exists, non-zero otherwise
        quoted_obb_path = shlex.quote(obb_android_path)
        cmd = ["adb", "shell", f"test -d {quoted_obb_path}"]
        _stdout, _stderr, code = self.run_adb_command(cmd)

        if code != 0:
            return True, "No OBB files found", None

        backup_dir = self.backup_base_dir / package_name
        backup_dir.mkdir(parents=True, exist_ok=True)

        obb_dest = backup_dir / "obb"

        # Pull OBB directory
        success, message = self.pull_file(obb_android_path, str(obb_dest), True)

        return success, message, str(obb_dest) if success else None

    def restore_apk_and_obb(self, backup_dir_path):
        """Restore APK and OBB files from backup - handles split APKs"""
        backup_dir = Path(backup_dir_path)

        # Find APK files
        apk_files = sorted(backup_dir.glob("*.apk"))
        if not apk_files:
            return False, "No APK file found in backup directory"

        # Check if it's a split APK (multiple APK files)
        is_split = len(apk_files) > 1

        # Install APK(s)
        if is_split:
            # Use install-multiple for split APKs
            success, message = self.install_multiple_apk(apk_files)
            if not success:
                return False, f"Failed to install split APKs: {message}"
        else:
            # Use regular install for single APK
            success, message = self.install_apk(str(apk_files[0]))
            if not success:
                return False, f"Failed to install APK: {message}"

        # Check for OBB directory
        obb_dir = backup_dir / "obb"
        if obb_dir.exists():
            # Get package name from backup metadata or directory name
            package_name = backup_dir.name
            # Use PurePosixPath for Android path construction
            obb_dest = str(PurePosixPath("/sdcard/Android/obb") / package_name)

            # Push OBB files
            success, message = self.push_file(str(obb_dir), obb_dest, True)
            if not success:
                return False, f"APK installed but failed to restore OBB: {message}"

            return True, f"Successfully restored {'split APK' if is_split else 'APK'} and OBB files"

        return True, f"Successfully restored {'split APK' if is_split else 'APK'} (no OBB files found)"

    def save_backup_metadata(self, package_name, package_info):
        """Save backup metadata to JSON file"""
        backup_dir = self.backup_base_dir / package_name
        metadata_path = backup_dir / "backup_info.json"

        metadata = {
            'package_name': package_name,
            'version_name': package_info.get('version_name', 'Unknown'),
            'version_code': package_info.get('version_code', 'Unknown'),
            'backup_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_split': package_info.get('is_split', False),
            'apk_count': len(package_info.get('apk_paths', []))
        }

        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

    def load_backup_metadata(self, package_name):
        """Load backup metadata from JSON file"""
        backup_dir = self.backup_base_dir / package_name
        metadata_path = backup_dir / "backup_info.json"

        if not metadata_path.exists():
            return None

        try:
            with open(metadata_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, PermissionError, OSError) as e:
            self.logger.error(f"Failed to load metadata for {package_name}: {str(e)}")
            return None

    def get_all_backups(self):
        """Get list of all available backups"""
        backups = []

        if not self.backup_base_dir.exists():
            return backups

        for backup_dir in self.backup_base_dir.iterdir():
            if backup_dir.is_dir():
                metadata = self.load_backup_metadata(backup_dir.name)
                if metadata:
                    backups.append(metadata)
                else:
                    # Create basic entry if no metadata
                    backups.append({
                        'package_name': backup_dir.name,
                        'version_name': 'Unknown',
                        'version_code': 'Unknown',
                        'backup_date': 'Unknown'
                    })

        return backups

    def delete_backup(self, package_name):
        """Delete a backup directory and all its contents"""
        backup_dir = self.backup_base_dir / package_name

        if not backup_dir.exists():
            return False, f"Backup not found for {package_name}"

        try:
            import shutil
            shutil.rmtree(backup_dir)
            self.logger.info(f"Backup deleted for {package_name}")
            return True, f"Backup deleted for {package_name}"
        except (PermissionError, OSError, FileNotFoundError) as e:
            error_msg = f"Failed to delete backup: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg


class ADBWorkerThread(QThread):
    """Worker thread for ADB operations to prevent UI freezing"""
    finished = pyqtSignal(bool, str)

    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args
        self._cancelled = False

    def cancel(self):
        """Request cancellation of the operation"""
        self._cancelled = True

    def is_cancelled(self):
        """Check if operation has been cancelled"""
        return self._cancelled

    def run(self):
        try:
            # Check if cancelled before starting
            if self._cancelled:
                self.finished.emit(False, "Operation cancelled by user")
                return

            success, message = self.operation(*self.args)

            # Check if cancelled after completion
            if self._cancelled:
                self.finished.emit(False, "Operation cancelled by user")
                return

            self.finished.emit(success, message)
        except (RuntimeError, ValueError, OSError, IOError) as e:
            # Handle specific exceptions that can occur during operations
            self.finished.emit(False, f"Operation error: {str(e)}")
        except Exception as e:
            # Catch any other unexpected exceptions
            self.finished.emit(False, f"Unexpected error: {str(e)}")


class AndroidFileManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.manager = AndroidFileManager()
        self.current_files = []
        self.init_ui()

        # Check if ADB is available before proceeding
        is_available, error_msg = self.manager.check_adb_available()
        if not is_available:
            QMessageBox.critical(
                self,
                "ADB Not Available",
                f"{error_msg}\n\nThe application may not function correctly without ADB."
            )
            self.statusBar().showMessage("ADB not available - Please install ADB")
        else:
            self.refresh_devices()
        
    def init_ui(self):
        self.setWindowTitle("Android File Manager - PyQt6")
        self.setGeometry(100, 100, 1200, 800)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(10)

        # Title and status row
        title_row = QHBoxLayout()
        title_label = QLabel("Android File Manager")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        title_row.addWidget(title_label)
        title_row.addStretch()

        self.status_label = QLabel("Not connected")
        self.status_label.setStyleSheet("color: red; font-size: 12px;")
        title_row.addWidget(self.status_label)
        main_layout.addLayout(title_row)

        # Device selection row
        device_row = QHBoxLayout()
        device_label = QLabel("Device:")
        device_row.addWidget(device_label)

        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(300)
        self.device_combo.currentTextChanged.connect(self.connect_to_device)
        device_row.addWidget(self.device_combo)

        refresh_devices_btn = QPushButton("Refresh Devices")
        refresh_devices_btn.clicked.connect(self.refresh_devices)
        device_row.addWidget(refresh_devices_btn)

        device_row.addStretch()

        install_apk_btn = QPushButton("Install APK")
        install_apk_btn.clicked.connect(self.install_apk)
        device_row.addWidget(install_apk_btn)

        main_layout.addLayout(device_row)

        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # File Browser Tab
        self.create_file_browser_tab()

        # Apps Manager Tab
        self.create_apps_manager_tab()

        # Status bar at bottom
        self.statusBar().showMessage("Ready")

    def create_file_browser_tab(self):
        """Create the file browser tab"""
        file_browser_widget = QWidget()
        file_browser_layout = QVBoxLayout(file_browser_widget)

        # Path navigation row
        path_row = QHBoxLayout()

        up_btn = QPushButton("↑ Up")
        up_btn.clicked.connect(self.go_up)
        path_row.addWidget(up_btn)

        path_label = QLabel("Path:")
        path_row.addWidget(path_label)

        self.path_edit = QLineEdit(self.manager.current_path)
        self.path_edit.returnPressed.connect(lambda: self.navigate_to_path(self.path_edit.text()))
        path_row.addWidget(self.path_edit)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(lambda: self.load_directory(self.manager.current_path))
        path_row.addWidget(refresh_btn)

        upload_file_btn = QPushButton("Upload File")
        upload_file_btn.clicked.connect(self.upload_file)
        path_row.addWidget(upload_file_btn)

        upload_folder_btn = QPushButton("Upload Folder")
        upload_folder_btn.clicked.connect(self.upload_folder)
        path_row.addWidget(upload_folder_btn)

        file_browser_layout.addLayout(path_row)

        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Type", "Permissions"])
        self.file_tree.setColumnWidth(0, 400)
        self.file_tree.setColumnWidth(1, 100)
        self.file_tree.setColumnWidth(2, 80)
        self.file_tree.setAlternatingRowColors(True)
        self.file_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.file_tree.itemDoubleClicked.connect(self.on_item_double_clicked)

        # Make header sections resizable
        header = self.file_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        file_browser_layout.addWidget(self.file_tree)

        self.tab_widget.addTab(file_browser_widget, "File Browser")

    def create_apps_manager_tab(self):
        """Create the apps manager tab"""
        apps_widget = QWidget()
        apps_layout = QVBoxLayout(apps_widget)

        # Button row
        button_row = QHBoxLayout()

        refresh_apps_btn = QPushButton("Refresh Apps Manager")
        refresh_apps_btn.clicked.connect(self.refresh_apps)
        button_row.addWidget(refresh_apps_btn)

        button_row.addStretch()

        apps_layout.addLayout(button_row)

        # Search row
        search_row = QHBoxLayout()

        search_label = QLabel("Search:")
        search_row.addWidget(search_label)

        self.apps_search_box = QLineEdit()
        self.apps_search_box.setPlaceholderText("Filter by package name...")
        self.apps_search_box.textChanged.connect(self.filter_apps)
        self.apps_search_box.setClearButtonEnabled(True)
        search_row.addWidget(self.apps_search_box)

        apps_layout.addLayout(search_row)

        # Apps table
        self.apps_table = QTableWidget()
        self.apps_table.setColumnCount(6)
        self.apps_table.setHorizontalHeaderLabels(["Package Name", "Version", "Backup Status", "Backup", "Restore", "Delete"])
        self.apps_table.setAlternatingRowColors(True)
        self.apps_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.apps_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # Set column widths
        header = self.apps_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        apps_layout.addWidget(self.apps_table)

        self.tab_widget.addTab(apps_widget, "Apps Manager")

    def refresh_apps(self):
        """Refresh the list of installed apps and backups"""
        if not self.manager.device_id:
            QMessageBox.warning(self, "No Device", "Please connect to a device first")
            return

        self.statusBar().showMessage("Loading apps and backups...")

        # Clean up cell widgets to prevent memory leaks
        for row in range(self.apps_table.rowCount()):
            for col in range(self.apps_table.columnCount()):
                widget = self.apps_table.cellWidget(row, col)
                if widget:
                    widget.deleteLater()

        self.apps_table.setRowCount(0)

        # Get list of installed packages
        packages, error = self.manager.list_installed_packages()
        if error:
            # Don't fail completely - we can still show backups
            packages = []

        # Get all backups
        backups = self.manager.get_all_backups()
        backup_dict = {b['package_name']: b for b in backups}

        # Create a combined set of all package names (installed OR backed up)
        all_package_names = set(packages) | set(backup_dict.keys())

        # Populate table
        for package_name in sorted(all_package_names):
            row = self.apps_table.rowCount()
            self.apps_table.insertRow(row)

            is_installed = package_name in packages
            has_backup = package_name in backup_dict

            # Package name (indicate if not installed)
            display_name = package_name
            if not is_installed:
                display_name = f"{package_name} [Not Installed]"
            self.apps_table.setItem(row, 0, QTableWidgetItem(display_name))

            # Version - get from backup metadata if available
            if has_backup:
                backup_info = backup_dict[package_name]
                version_name = backup_info.get('version_name', 'Unknown')
                self.apps_table.setItem(row, 1, QTableWidgetItem(version_name))
            else:
                self.apps_table.setItem(row, 1, QTableWidgetItem("-"))

            # Backup status
            if has_backup:
                backup_info = backup_dict[package_name]
                backup_date = backup_info.get('backup_date', 'Unknown')
                status_text = f"✓ {backup_date}"
            else:
                status_text = "Not backed up"
            self.apps_table.setItem(row, 2, QTableWidgetItem(status_text))

            # Backup button (only if installed)
            if is_installed:
                backup_btn = QPushButton("Backup")
                backup_btn.clicked.connect(lambda _, pkg=package_name: self.backup_app(pkg))
                self.apps_table.setCellWidget(row, 3, backup_btn)
            else:
                self.apps_table.setItem(row, 3, QTableWidgetItem(""))

            # Restore button (only if has backup)
            if has_backup:
                restore_btn = QPushButton("Restore")
                restore_btn.clicked.connect(lambda _, pkg=package_name: self.restore_app(pkg))
                self.apps_table.setCellWidget(row, 4, restore_btn)
            else:
                self.apps_table.setItem(row, 4, QTableWidgetItem(""))

            # Delete backup button (only if has backup)
            if has_backup:
                delete_btn = QPushButton("Delete Backup")
                delete_btn.clicked.connect(lambda _, pkg=package_name: self.delete_backup(pkg))
                self.apps_table.setCellWidget(row, 5, delete_btn)
            else:
                self.apps_table.setItem(row, 5, QTableWidgetItem(""))

        self.statusBar().showMessage(f"Loaded {len(all_package_names)} total apps ({len(packages)} installed, {len(backups)} backups)")

    def filter_apps(self, search_text):
        """Filter apps table based on search text"""
        search_text = search_text.lower()

        for row in range(self.apps_table.rowCount()):
            # Get package name from first column
            item = self.apps_table.item(row, 0)
            if item:
                package_name = item.text().lower()

                # Show row if search text is in package name, otherwise hide
                if search_text in package_name:
                    self.apps_table.setRowHidden(row, False)
                else:
                    self.apps_table.setRowHidden(row, True)

    def backup_app(self, package_name):
        """Backup an app (APK + OBB)"""
        reply = QMessageBox.question(
            self,
            "Confirm Backup",
            f"Backup {package_name}?\n\nThis will backup the APK and OBB files (if any).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Show progress dialog
        progress = QProgressDialog(f"Backing up {package_name}...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Backing up")
        progress.show()

        # Create worker thread
        worker = ADBWorkerThread(self._perform_backup, package_name)
        worker.finished.connect(lambda success, msg: self.backup_finished(success, msg, package_name, progress))

        # Connect cancel button to worker cancellation
        progress.canceled.connect(worker.cancel)

        worker.start()

        self.current_worker = worker

    def _perform_backup(self, package_name):
        """Perform the actual backup operation"""
        # Get package info
        package_info, error = self.manager.get_package_info(package_name)
        if error:
            return False, f"Failed to get package info: {error}"

        # Backup APK
        success, message, apk_path = self.manager.backup_apk(package_name, package_info)
        if not success:
            return False, f"Failed to backup APK: {message}"

        # Backup OBB
        success, message, _obb_path = self.manager.backup_obb(package_name)
        if not success and "No OBB files found" not in message:
            return False, f"Failed to backup OBB: {message}"

        # Save metadata
        self.manager.save_backup_metadata(package_name, package_info)

        return True, f"Successfully backed up to:\n{apk_path}"

    def backup_finished(self, success, message, package_name, progress_dialog):
        """Handle backup completion"""
        progress_dialog.close()

        if success:
            QMessageBox.information(self, "Success", f"Backup completed for {package_name}\n\n{message}")
            self.refresh_apps()
        else:
            QMessageBox.critical(self, "Backup Failed", f"Failed to backup {package_name}:\n{message}")

    def restore_app(self, package_name):
        """Restore an app from backup"""
        reply = QMessageBox.question(
            self,
            "Confirm Restore",
            f"Restore {package_name}?\n\nThis will install the APK and restore OBB files (if any).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        backup_dir = self.manager.backup_base_dir / package_name

        if not backup_dir.exists():
            QMessageBox.critical(self, "Error", f"Backup directory not found for {package_name}")
            return

        # Show progress dialog
        progress = QProgressDialog(f"Restoring {package_name}...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Restoring")
        progress.show()

        # Create worker thread
        worker = ADBWorkerThread(self.manager.restore_apk_and_obb, str(backup_dir))
        worker.finished.connect(lambda success, msg: self.restore_finished(success, msg, package_name, progress))

        # Connect cancel button to worker cancellation
        progress.canceled.connect(worker.cancel)

        worker.start()

        self.current_worker = worker

    def restore_finished(self, success, message, package_name, progress_dialog):
        """Handle restore completion"""
        progress_dialog.close()

        if success:
            QMessageBox.information(self, "Success", f"Restore completed for {package_name}\n\n{message}")
            self.refresh_apps()
        else:
            QMessageBox.critical(self, "Restore Failed", f"Failed to restore {package_name}:\n{message}")

    def delete_backup(self, package_name):
        """Delete a backup for an app"""
        # Load backup info to show details
        backup_info = self.manager.load_backup_metadata(package_name)

        if backup_info:
            backup_date = backup_info.get('backup_date', 'Unknown')
            is_split = backup_info.get('is_split', False)
            apk_type = "Split APK" if is_split else "APK"
            details = f"\nBackup date: {backup_date}\nType: {apk_type}"
        else:
            details = ""

        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Delete backup for {package_name}?{details}\n\nThis will permanently delete the backup files (APK and OBB).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Delete the backup
        success, message = self.manager.delete_backup(package_name)

        if success:
            QMessageBox.information(self, "Success", message)
            self.refresh_apps()
        else:
            QMessageBox.critical(self, "Delete Failed", f"Failed to delete backup:\n{message}")

    def show_context_menu(self, position):
        """Show right-click context menu"""
        item = self.file_tree.itemAt(position)
        if not item:
            return
        
        file_info = item.data(0, Qt.ItemDataRole.UserRole)
        if not file_info:
            return
        
        menu = QMenu()
        
        if file_info['is_dir']:
            open_action = QAction("Open", self)
            open_action.triggered.connect(lambda: self.navigate_to_path(file_info['path']))
            menu.addAction(open_action)
        
        download_action = QAction("Download", self)
        download_action.triggered.connect(lambda: self.pull_file(file_info))
        menu.addAction(download_action)
        
        menu.addSeparator()
        
        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(lambda: self.delete_file(file_info))
        menu.addAction(delete_action)
        
        menu.exec(self.file_tree.viewport().mapToGlobal(position))
        
    def on_item_double_clicked(self, item, _column):
        """Handle double-click on tree item - navigate and refresh immediately"""
        if not item:
            return

        # Get file info from item data
        file_info = item.data(0, Qt.ItemDataRole.UserRole)

        # Validate file_info exists and has required fields
        if not file_info:
            self.statusBar().showMessage("Error: No file information found for item")
            return

        if not isinstance(file_info, dict):
            self.statusBar().showMessage("Error: Invalid file information format")
            return

        # Check if it's a directory and has a path
        if file_info.get('is_dir') and file_info.get('path'):
            # Navigate will automatically refresh the directory
            self.navigate_to_path(file_info['path'])
    
    def refresh_devices(self):
        """Refresh list of connected devices"""
        devices = self.manager.get_connected_devices()
        self.device_combo.clear()
        
        if devices:
            self.device_combo.addItems(devices)
            self.connect_to_device(devices[0])
        else:
            self.status_label.setText("No devices connected")
            self.status_label.setStyleSheet("color: red; font-size: 12px;")
            self.statusBar().showMessage("No devices connected")
    
    def connect_to_device(self, device_id):
        """Connect to selected device"""
        if not device_id:
            return
        
        self.manager.device_id = device_id
        self.status_label.setText(f"Connected: {device_id}")
        self.status_label.setStyleSheet("color: green; font-size: 12px;")
        self.statusBar().showMessage(f"Connected to {device_id}")
        self.load_directory(self.manager.current_path)
    
    def navigate_to_path(self, path):
        """Navigate to specified path and refresh immediately"""
        # Validate path parameter
        if not path:
            self.statusBar().showMessage("Error: Invalid path")
            return

        # Normalize the path to ensure consistency
        try:
            normalized_path = str(PurePosixPath(path))
        except Exception as e:
            self.statusBar().showMessage(f"Error: Invalid path format - {str(e)}")
            return

        # Update current path and UI
        self.manager.current_path = normalized_path
        self.path_edit.setText(normalized_path)

        # Show navigation status
        self.statusBar().showMessage(f"Navigating to {normalized_path}...")

        # Always refresh directory contents immediately
        self.load_directory(normalized_path)
    
    def go_up(self):
        """Go to parent directory"""
        # Use PurePosixPath for proper path manipulation
        current = PurePosixPath(self.manager.current_path)
        parent = str(current.parent)
        # Only navigate if parent is different (prevents going above root)
        if parent != self.manager.current_path and parent != '.':
            self.navigate_to_path(parent)
    
    def load_directory(self, path):
        """Load and display directory contents"""
        self.statusBar().showMessage(f"Loading {path}...")

        # Clear the tree widget
        self.file_tree.clear()

        # Force UI update to show the cleared tree immediately
        QApplication.processEvents()

        # Get directory contents
        files, error = self.manager.list_directory(path)

        if error:
            QMessageBox.critical(self, "Error", f"Failed to load directory:\n{error}")
            self.statusBar().showMessage("Error loading directory")
            return

        # Validate files is a list
        if not isinstance(files, list):
            self.statusBar().showMessage("Error: Invalid directory data received")
            return

        # Sort: directories first, then by name
        files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        self.current_files = files

        # Populate the tree widget
        for file in files:
            item = QTreeWidgetItem()

            # Name
            icon = "📁" if file['is_dir'] else "📄"
            item.setText(0, f"{icon} {file['name']}")

            # Size
            if file['is_dir']:
                item.setText(1, "DIR")
            else:
                try:
                    size_text = self.format_size(int(file['size']))
                    item.setText(1, size_text)
                except (ValueError, TypeError):
                    item.setText(1, "?")

            # Type
            item.setText(2, "Folder" if file['is_dir'] else "File")

            # Permissions
            item.setText(3, file['permissions'])

            # Store file info in item
            item.setData(0, Qt.ItemDataRole.UserRole, file)

            self.file_tree.addTopLevelItem(item)

        # Force UI update to ensure all items are displayed immediately
        self.file_tree.update()
        QApplication.processEvents()

        self.statusBar().showMessage(f"Loaded {len(files)} items from {path}")
    
    def format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def upload_file(self):
        """Upload a file to Android device"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Upload",
            self.manager.local_path,
            "All Files (*.*)"
        )
        
        if file_path:
            self.perform_upload(file_path, False)
    
    def upload_folder(self):
        """Upload a folder to Android device"""
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to Upload",
            self.manager.local_path
        )
        
        if folder_path:
            self.perform_upload(folder_path, True)
    
    def perform_upload(self, local_path, is_dir):
        """Perform the actual upload operation"""
        if not os.path.exists(local_path):
            QMessageBox.critical(self, "Error", f"File not found: {local_path}")
            return
        
        file_name = os.path.basename(local_path)
        # Use PurePosixPath for Android path construction
        dest_path = str(PurePosixPath(self.manager.current_path) / file_name)
        
        # Show progress dialog
        progress = QProgressDialog(f"Uploading {file_name}...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Uploading")
        progress.show()
        
        # Create worker thread
        worker = ADBWorkerThread(self.manager.push_file, local_path, dest_path, is_dir)
        worker.finished.connect(lambda success, msg: self.upload_finished(success, msg, file_name, progress))

        # Connect cancel button to worker cancellation
        progress.canceled.connect(worker.cancel)

        worker.start()

        # Store worker reference to prevent garbage collection
        self.current_worker = worker
    
    def upload_finished(self, success, message, file_name, progress_dialog):
        """Handle upload completion"""
        progress_dialog.close()
        
        if success:
            QMessageBox.information(self, "Success", f"Uploaded {file_name} to {self.manager.current_path}")
            self.load_directory(self.manager.current_path)
        else:
            QMessageBox.critical(self, "Upload Failed", f"Failed to upload {file_name}:\n{message}")
    
    def pull_file(self, file_info):
        """Download file from Android device"""
        # Ask user where to save
        if file_info['is_dir']:
            local_dest = QFileDialog.getExistingDirectory(
                self,
                f"Select destination for folder: {file_info['name']}",
                self.manager.local_path
            )
            if local_dest:
                local_dest = os.path.join(local_dest, file_info['name'])
        else:
            local_dest, _ = QFileDialog.getSaveFileName(
                self,
                "Save File As",
                os.path.join(self.manager.local_path, file_info['name']),
                "All Files (*.*)"
            )
        
        if not local_dest:
            return
        
        # Show progress dialog
        progress = QProgressDialog(f"Downloading {file_info['name']}...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Downloading")
        progress.show()
        
        # Create worker thread
        worker = ADBWorkerThread(self.manager.pull_file, file_info['path'], local_dest, file_info['is_dir'])
        worker.finished.connect(lambda success, msg: self.download_finished(success, msg, file_info['name'], local_dest, progress))

        # Connect cancel button to worker cancellation
        progress.canceled.connect(worker.cancel)

        worker.start()

        self.current_worker = worker
    
    def download_finished(self, success, message, file_name, local_dest, progress_dialog):
        """Handle download completion"""
        progress_dialog.close()
        
        if success:
            QMessageBox.information(self, "Success", f"Downloaded {file_name} to:\n{local_dest}")
        else:
            QMessageBox.critical(self, "Download Failed", f"Failed to download {file_name}:\n{message}")
    
    def delete_file(self, file_info):
        """Delete file from Android device"""
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete:\n{file_info['name']}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            progress = QProgressDialog(f"Deleting {file_info['name']}...", "Cancel", 0, 0, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.setWindowTitle("Deleting")
            progress.show()

            worker = ADBWorkerThread(self.manager.delete_file, file_info['path'])
            worker.finished.connect(lambda success, msg: self.delete_finished(success, msg, file_info['name'], progress))

            # Connect cancel button to worker cancellation
            progress.canceled.connect(worker.cancel)

            worker.start()

            self.current_worker = worker
    
    def delete_finished(self, success, message, file_name, progress_dialog):
        """Handle delete completion"""
        progress_dialog.close()
        
        if success:
            QMessageBox.information(self, "Success", f"Deleted {file_name}")
            self.load_directory(self.manager.current_path)
        else:
            QMessageBox.critical(self, "Delete Failed", f"Failed to delete {file_name}:\n{message}")
    
    def install_apk(self):
        """Install APK file on Android device"""
        apk_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select APK to Install",
            self.manager.local_path,
            "APK Files (*.apk)"
        )
        
        if not apk_path:
            return
        
        apk_name = os.path.basename(apk_path)
        
        progress = QProgressDialog(f"Installing {apk_name}...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Installing APK")
        progress.show()

        worker = ADBWorkerThread(self.manager.install_apk, apk_path)
        worker.finished.connect(lambda success, msg: self.install_finished(success, msg, apk_name, progress))

        # Connect cancel button to worker cancellation
        progress.canceled.connect(worker.cancel)

        worker.start()

        self.current_worker = worker
    
    def install_finished(self, success, message, apk_name, progress_dialog):
        """Handle APK installation completion"""
        progress_dialog.close()
        
        if success:
            QMessageBox.information(self, "Success", f"Successfully installed {apk_name}")
        else:
            QMessageBox.critical(self, "Installation Failed", f"Failed to install {apk_name}:\n{message}")


def main():
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    window = AndroidFileManagerWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()