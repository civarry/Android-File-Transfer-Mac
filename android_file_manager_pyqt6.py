import sys
import subprocess
import os
import shlex
from pathlib import Path
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QLineEdit, QTreeWidget, QTreeWidgetItem,
    QFileDialog, QMessageBox, QProgressDialog, QHeaderView, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QAction


class AndroidFileManager:
    def __init__(self):
        self.current_path = "/storage/emulated/0"
        self.device_id = None
        self.local_path = str(Path.home() / "Downloads")
        
    def run_adb_command(self, command):
        """Execute ADB command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return None, "Command timed out", 1
        except Exception as e:
            return None, str(e), 1
    
    def get_connected_devices(self):
        """Get list of connected Android devices"""
        stdout, stderr, code = self.run_adb_command("adb devices")
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
        # Quote the entire shell command so the path with spaces is preserved
        cmd = f"adb shell \"ls -la {shlex.quote(path)}\""
        stdout, stderr, code = self.run_adb_command(cmd)
        
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
            
            files.append({
                'name': name,
                'is_dir': is_dir,
                'size': size,
                'permissions': permissions,
                'path': f"{path}/{name}".replace('//', '/')
            })
        
        return files, None
    
    def pull_file(self, android_path, local_path, is_dir=False):
        """Pull file or directory from Android to local machine"""
        if is_dir:
            cmd = f"adb pull -a {shlex.quote(android_path)} {shlex.quote(local_path)}"
        else:
            cmd = f"adb pull {shlex.quote(android_path)} {shlex.quote(local_path)}"
        stdout, stderr, code = self.run_adb_command(cmd)
        return code == 0, stderr if code != 0 else stdout
    
    def push_file(self, local_path, android_path, is_dir=False):
        """Push file or directory from local machine to Android"""
        cmd = f"adb push {shlex.quote(local_path)} {shlex.quote(android_path)}"
        stdout, stderr, code = self.run_adb_command(cmd)
        return code == 0, stderr if code != 0 else stdout
    
    def delete_file(self, android_path):
        """Delete file or directory on Android"""
        # Quote the entire shell command so the path with spaces is preserved
        cmd = f"adb shell \"rm -rf {shlex.quote(android_path)}\""
        stdout, stderr, code = self.run_adb_command(cmd)
        return code == 0, stderr if code != 0 else stdout
    
    def install_apk(self, apk_path):
        """Install APK file"""
        cmd = f"adb install {shlex.quote(apk_path)}"
        stdout, stderr, code = self.run_adb_command(cmd)
        return code == 0, stdout + stderr


class ADBWorkerThread(QThread):
    """Worker thread for ADB operations to prevent UI freezing"""
    finished = pyqtSignal(bool, str)
    
    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args
    
    def run(self):
        try:
            success, message = self.operation(*self.args)
            self.finished.emit(success, message)
        except Exception as e:
            self.finished.emit(False, str(e))


class AndroidFileManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.manager = AndroidFileManager()
        self.current_files = []
        self.init_ui()
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
        
        main_layout.addLayout(path_row)
        
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
        
        main_layout.addWidget(self.file_tree)
        
        # Status bar at bottom
        self.statusBar().showMessage("Ready")
        
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
        
    def on_item_double_clicked(self, item, column):
        """Handle double-click on tree item"""
        file_info = item.data(0, Qt.ItemDataRole.UserRole)
        if file_info and file_info['is_dir']:
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
        """Navigate to specified path"""
        self.manager.current_path = path
        self.path_edit.setText(path)
        self.load_directory(path)
    
    def go_up(self):
        """Go to parent directory"""
        parent = str(Path(self.manager.current_path).parent)
        if parent != self.manager.current_path:
            self.navigate_to_path(parent)
    
    def load_directory(self, path):
        """Load and display directory contents"""
        self.statusBar().showMessage(f"Loading {path}...")
        self.file_tree.clear()
        
        files, error = self.manager.list_directory(path)
        
        if error:
            QMessageBox.critical(self, "Error", f"Failed to load directory:\n{error}")
            self.statusBar().showMessage("Error loading directory")
            return
        
        # Sort: directories first, then by name
        files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        self.current_files = files
        
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
        dest_path = os.path.join(self.manager.current_path, file_name).replace('\\', '/')
        
        # Show progress dialog
        progress = QProgressDialog(f"Uploading {file_name}...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Uploading")
        progress.show()
        
        # Create worker thread
        worker = ADBWorkerThread(self.manager.push_file, local_path, dest_path, is_dir)
        worker.finished.connect(lambda success, msg: self.upload_finished(success, msg, file_name, progress))
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
            progress = QProgressDialog(f"Deleting {file_info['name']}...", None, 0, 0, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.setWindowTitle("Deleting")
            progress.show()
            
            worker = ADBWorkerThread(self.manager.delete_file, file_info['path'])
            worker.finished.connect(lambda success, msg: self.delete_finished(success, msg, file_info['name'], progress))
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