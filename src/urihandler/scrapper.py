# -*- coding: utf-8 -*-
import os
import re
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import pyautogui
import pyperclip
import time
import threading
import subprocess
import sys
from datetime import datetime
import json

MAX_CHARACTERS = 100000

class CHeaderDumper:
    def __init__(self, root):
        self.root = root
        self.root.title("C++ Development Suite (Dark Mode)")
        self.root.geometry("1400x900")
        self.root.configure(bg="#1e1e1e")

        self.text_boxes = []
        self.running_process = None
        self.gdb_process = None
        self.make_process = None
        self.project_stats = {}

        # Create main container with notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Configure notebook style for dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1e1e1e', borderwidth=0)
        style.configure('TNotebook.Tab', background='#2d2d30', foreground='#cccccc', 
                       padding=[20, 8], borderwidth=0)
        style.map('TNotebook.Tab', background=[('selected', '#007ACC')])

        # === PROJECT OVERVIEW TAB ===
        self.overview_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.overview_frame, text="ðﾟﾓﾊ Project Overview")
        self.setup_overview_tab()

        # === FILES TAB ===
        self.files_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.files_frame, text="ðﾟﾓﾁ Files")
        self.setup_files_tab()

        # === MAKE TAB ===
        self.make_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.make_frame, text="ðﾟﾔﾨ Make")
        self.setup_make_tab()

        # === RUNNER TAB ===
        self.runner_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.runner_frame, text="▶️ Runner")
        self.setup_runner_tab()

        # === DEBUGGER TAB ===
        self.debugger_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.debugger_frame, text="ðﾟﾐﾛ GDB")
        self.setup_debugger_tab()

        self.refresh_files()

    def setup_overview_tab(self):
        # Control panel
        overview_control_frame = tk.Frame(self.overview_frame, bg="#1e1e1e")
        overview_control_frame.pack(fill=tk.X, padx=10, pady=10)

        self.analyze_btn = tk.Button(
            overview_control_frame, text="ðﾟﾔﾍ Analyze Project", command=self.analyze_project,
            bg="#4CAF50", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=5)

        self.export_stats_btn = tk.Button(
            overview_control_frame, text="ðﾟﾓﾤ Export Stats", command=self.export_stats,
            bg="#2196F3", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.export_stats_btn.pack(side=tk.LEFT, padx=5)

        self.copy_overview_btn = tk.Button(
            overview_control_frame, text="ðﾟﾓﾋ Copy Overview", command=self.copy_overview,
            bg="#FF9800", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.copy_overview_btn.pack(side=tk.LEFT, padx=5)

        # Last analyzed time
        self.last_analyzed_label = tk.Label(
            overview_control_frame, text="Not analyzed yet", font=("JetBrains Mono", 9),
            fg="#888888", bg="#1e1e1e"
        )
        self.last_analyzed_label.pack(side=tk.RIGHT, padx=10)

        # Main content area with scrollable frame
        main_content_frame = tk.Frame(self.overview_frame, bg="#1e1e1e")
        main_content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Create canvas and scrollbar for overview content
        self.overview_canvas = tk.Canvas(main_content_frame, bg="#1e1e1e", highlightthickness=0)
        self.overview_scrollbar = tk.Scrollbar(main_content_frame, orient="vertical", command=self.overview_canvas.yview)
        self.overview_content_frame = tk.Frame(self.overview_canvas, bg="#1e1e1e")

        self.overview_content_frame.bind("<Configure>", lambda e: self.overview_canvas.configure(scrollregion=self.overview_canvas.bbox("all")))
        self.overview_canvas.create_window((0, 0), window=self.overview_content_frame, anchor="nw")
        self.overview_canvas.configure(yscrollcommand=self.overview_scrollbar.set)

        self.overview_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.overview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Initialize with placeholder content
        self.create_overview_placeholder()

    def create_overview_placeholder(self):
        placeholder_label = tk.Label(
            self.overview_content_frame, 
            text="ðﾟﾓﾊ Click 'Analyze Project' to generate comprehensive project statistics",
            font=("JetBrains Mono", 14), fg="#888888", bg="#1e1e1e"
        )
        placeholder_label.pack(expand=True, pady=50)

    def analyze_project(self):
        """Analyze the entire project and generate comprehensive statistics"""
        self.analyze_btn.config(text="ðﾟﾔﾄ Analyzing...", state=tk.DISABLED)
        self.root.update()

        # Clear previous content
        for widget in self.overview_content_frame.winfo_children():
            widget.destroy()

        # Analyze project in a separate thread to avoid blocking UI
        threading.Thread(target=self._perform_analysis, daemon=True).start()

    def _perform_analysis(self):
        """Perform the actual project analysis"""
        try:
            stats = self.calculate_project_stats()
            self.project_stats = stats
            
            # Update UI in main thread
            self.root.after(0, lambda: self._display_analysis_results(stats))
            
        except Exception as e:
            self.root.after(0, lambda: self._display_analysis_error(str(e)))

    def calculate_project_stats(self):
        """Calculate comprehensive project statistics"""
        stats = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'files': {},
            'totals': {
                'files': 0,
                'total_lines': 0,
                'code_lines': 0,
                'comment_lines': 0,
                'blank_lines': 0,
                'total_chars': 0,
                'functions': 0,
                'classes': 0,
                'includes': 0
            },
            'file_types': {},
            'largest_files': [],
            'complexity': {
                'cyclomatic_complexity': 0,
                'nested_depth': 0
            },
            'dependencies': set(),
            'build_info': {}
        }

        directories = ["", "helpers", "packages"]
        
        for directory in directories:
            path = os.path.join(os.getcwd(), directory)
            if not os.path.exists(path):
                continue

            for filename in os.listdir(path):
                if filename.endswith(('.cpp', '.hpp', '.h', '.c', '.cc', '.cxx')):
                    full_path = os.path.join(path, filename)
                    if os.path.isfile(full_path):
                        file_stats = self.analyze_file(full_path, directory, filename)
                        stats['files'][full_path] = file_stats
                        
                        # Update totals
                        stats['totals']['files'] += 1
                        stats['totals']['total_lines'] += file_stats['total_lines']
                        stats['totals']['code_lines'] += file_stats['code_lines']
                        stats['totals']['comment_lines'] += file_stats['comment_lines']
                        stats['totals']['blank_lines'] += file_stats['blank_lines']
                        stats['totals']['total_chars'] += file_stats['total_chars']
                        stats['totals']['functions'] += file_stats['functions']
                        stats['totals']['classes'] += file_stats['classes']
                        stats['totals']['includes'] += file_stats['includes']
                        
                        # Update file types
                        ext = os.path.splitext(filename)[1]
                        if ext not in stats['file_types']:
                            stats['file_types'][ext] = {'count': 0, 'lines': 0}
                        stats['file_types'][ext]['count'] += 1
                        stats['file_types'][ext]['lines'] += file_stats['code_lines']
                        
                        # Track dependencies
                        stats['dependencies'].update(file_stats['dependencies'])

        # Convert set to list for JSON serialization
        stats['dependencies'] = list(stats['dependencies'])
        
        # Find largest files
        stats['largest_files'] = sorted(
            [(path, data['code_lines']) for path, data in stats['files'].items()],
            key=lambda x: x[1], reverse=True
        )[:10]

        # Check for build files
        stats['build_info'] = self.analyze_build_files()

        return stats

    def analyze_file(self, file_path, directory, filename):
        """Analyze a single file and return statistics"""
        file_stats = {
            'filename': filename,
            'directory': directory,
            'total_lines': 0,
            'code_lines': 0,
            'comment_lines': 0,
            'blank_lines': 0,
            'total_chars': 0,
            'functions': 0,
            'classes': 0,
            'includes': 0,
            'dependencies': set(),
            'complexity_score': 0
        }

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            file_stats['total_chars'] = len(content)
            file_stats['total_lines'] = len(lines)

            in_multiline_comment = False
            
            for line in lines:
                stripped = line.strip()
                
                if not stripped:
                    file_stats['blank_lines'] += 1
                    continue
                
                # Handle multi-line comments
                if '/*' in stripped and '*/' in stripped:
                    # Single line /* */ comment
                    file_stats['comment_lines'] += 1
                    continue
                elif '/*' in stripped:
                    in_multiline_comment = True
                    file_stats['comment_lines'] += 1
                    continue
                elif '*/' in stripped:
                    in_multiline_comment = False
                    file_stats['comment_lines'] += 1
                    continue
                elif in_multiline_comment:
                    file_stats['comment_lines'] += 1
                    continue
                
                # Handle single line comments
                if stripped.startswith('//'):
                    file_stats['comment_lines'] += 1
                    continue
                
                # This is a code line
                file_stats['code_lines'] += 1
                
                # Count various elements
                if re.search(r'#include\s*[<"]', stripped):
                    file_stats['includes'] += 1
                    # Extract dependency
                    match = re.search(r'#include\s*[<"]([^>"]+)[>"]', stripped)
                    if match:
                        file_stats['dependencies'].add(match.group(1))
                
                # Count functions (simple heuristic)
                if re.search(r'\w+\s*\([^)]*\)\s*\{', stripped) or re.search(r'\w+\s*\([^)]*\)\s*$', stripped):
                    file_stats['functions'] += 1
                
                # Count classes
                if re.search(r'\bclass\s+\w+', stripped) or re.search(r'\bstruct\s+\w+', stripped):
                    file_stats['classes'] += 1
                
                # Simple complexity indicators
                complexity_keywords = ['if', 'else', 'for', 'while', 'switch', 'case', 'catch']
                for keyword in complexity_keywords:
                    if re.search(r'\b' + keyword + r'\b', stripped):
                        file_stats['complexity_score'] += 1

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

        return file_stats

    def analyze_build_files(self):
        """Analyze build-related files"""
        build_info = {
            'makefile': None,
            'cmake': None,
            'executable': None
        }

        # Check for Makefile
        makefiles = ["Makefile", "makefile", "GNUmakefile"]
        for makefile in makefiles:
            if os.path.exists(makefile):
                build_info['makefile'] = {
                    'name': makefile,
                    'size': os.path.getsize(makefile),
                    'modified': datetime.fromtimestamp(os.path.getmtime(makefile)).strftime("%Y-%m-%d %H:%M:%S")
                }
                break

        # Check for CMake
        if os.path.exists("CMakeLists.txt"):
            build_info['cmake'] = {
                'size': os.path.getsize("CMakeLists.txt"),
                'modified': datetime.fromtimestamp(os.path.getmtime("CMakeLists.txt")).strftime("%Y-%m-%d %H:%M:%S")
            }

        # Check for executable
        if os.path.exists("main.exe"):
            build_info['executable'] = {
                'size': os.path.getsize("main.exe"),
                'modified': datetime.fromtimestamp(os.path.getmtime("main.exe")).strftime("%Y-%m-%d %H:%M:%S")
            }

        return build_info

    def _display_analysis_results(self, stats):
        """Display the analysis results in the UI"""
        # Clear any existing content
        for widget in self.overview_content_frame.winfo_children():
            widget.destroy()

        # Create main sections
        self.create_summary_section(stats)
        self.create_file_breakdown_section(stats)
        self.create_complexity_section(stats)
        self.create_dependencies_section(stats)
        self.create_build_info_section(stats)
        self.create_detailed_files_section(stats)

        # Update last analyzed time
        self.last_analyzed_label.config(text=f"Last analyzed: {stats['timestamp']}")
        
        # Re-enable analyze button
        self.analyze_btn.config(text="ðﾟﾔﾍ Analyze Project", state=tk.NORMAL)

        def create_summary_section(self, stats):
            """Create the project summary section"""
        summary_frame = tk.LabelFrame(
            self.overview_content_frame, text="ðﾟﾓﾊ Project Summary", 
            font=("JetBrains Mono", 12, "bold"), fg="#4CAF50", bg="#1e1e1e"
        )
        summary_frame.pack(fill=tk.X, padx=10, pady=10)

        # Create grid layout for summary stats
        summary_grid = tk.Frame(summary_frame, bg="#1e1e1e")
        summary_grid.pack(fill=tk.X, padx=10, pady=10)

        # Summary statistics
        summary_stats = [
            ("ðﾟﾓﾁ Total Files", stats['totals']['files']),
            ("ðﾟﾓﾝ Total Lines", f"{stats['totals']['total_lines']:,}"),
            ("ðﾟﾒﾻ Code Lines", f"{stats['totals']['code_lines']:,}"),
            ("ðﾟﾒﾬ Comment Lines", f"{stats['totals']['comment_lines']:,}"),
            ("⚪ Blank Lines", f"{stats['totals']['blank_lines']:,}"),
            ("ðﾟﾔﾤ Total Characters", f"{stats['totals']['total_chars']:,}"),
            ("⚙️ Functions", stats['totals']['functions']),
            ("ðﾟﾏﾗ️ Classes/Structs", stats['totals']['classes']),
            ("ðﾟﾓﾦ Includes", stats['totals']['includes'])
        ]

        # Calculate percentages
        total_lines = stats['totals']['total_lines']
        if total_lines > 0:
            code_percent = (stats['totals']['code_lines'] / total_lines) * 100
            comment_percent = (stats['totals']['comment_lines'] / total_lines) * 100
            blank_percent = (stats['totals']['blank_lines'] / total_lines) * 100
        else:
            code_percent = comment_percent = blank_percent = 0

        for i, (label, value) in enumerate(summary_stats):
            row = i // 3
            col = i % 3
            
            stat_frame = tk.Frame(summary_grid, bg="#2d2d30", relief=tk.RAISED, bd=1)
            stat_frame.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
            summary_grid.grid_columnconfigure(col, weight=1)
            
            tk.Label(stat_frame, text=label, font=("JetBrains Mono", 9), 
                    fg="#cccccc", bg="#2d2d30").pack(pady=(5, 0))
            tk.Label(stat_frame, text=str(value), font=("JetBrains Mono", 11, "bold"), 
                    fg="#4CAF50", bg="#2d2d30").pack(pady=(0, 5))

        # Add percentage breakdown
        percentage_frame = tk.Frame(summary_frame, bg="#1e1e1e")
        percentage_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Label(percentage_frame, text="ðﾟﾓﾊ Line Distribution:", 
                font=("JetBrains Mono", 10, "bold"), fg="#cccccc", bg="#1e1e1e").pack(anchor="w")
        
        distribution_text = f"Code: {code_percent:.1f}% | Comments: {comment_percent:.1f}% | Blank: {blank_percent:.1f}%"
        tk.Label(percentage_frame, text=distribution_text, 
                font=("JetBrains Mono", 9), fg="#888888", bg="#1e1e1e").pack(anchor="w")

    def create_file_breakdown_section(self, stats):
        """Create the file type breakdown section"""
        breakdown_frame = tk.LabelFrame(
            self.overview_content_frame, text="ðﾟﾓﾂ File Type Breakdown", 
            font=("JetBrains Mono", 12, "bold"), fg="#2196F3", bg="#1e1e1e"
        )
        breakdown_frame.pack(fill=tk.X, padx=10, pady=10)

        breakdown_content = tk.Frame(breakdown_frame, bg="#1e1e1e")
        breakdown_content.pack(fill=tk.X, padx=10, pady=10)

        for ext, data in stats['file_types'].items():
            file_type_frame = tk.Frame(breakdown_content, bg="#2d2d30", relief=tk.RAISED, bd=1)
            file_type_frame.pack(fill=tk.X, pady=2)
            
            info_text = f"{ext} files: {data['count']} files, {data['lines']:,} lines of code"
            tk.Label(file_type_frame, text=info_text, font=("JetBrains Mono", 9), 
                    fg="#cccccc", bg="#2d2d30").pack(anchor="w", padx=10, pady=5)

    def create_complexity_section(self, stats):
        """Create the complexity analysis section"""
        complexity_frame = tk.LabelFrame(
            self.overview_content_frame, text="ðﾟﾧﾮ Complexity Analysis", 
            font=("JetBrains Mono", 12, "bold"), fg="#FF9800", bg="#1e1e1e"
        )
        complexity_frame.pack(fill=tk.X, padx=10, pady=10)

        complexity_content = tk.Frame(complexity_frame, bg="#1e1e1e")
        complexity_content.pack(fill=tk.X, padx=10, pady=10)

        # Calculate average complexity
        total_complexity = sum(file_data['complexity_score'] for file_data in stats['files'].values())
        avg_complexity = total_complexity / max(stats['totals']['files'], 1)
        
        # Calculate lines per function
        lines_per_function = stats['totals']['code_lines'] / max(stats['totals']['functions'], 1)

        complexity_stats = [
            ("ðﾟﾔﾄ Total Complexity Score", total_complexity),
            ("ðﾟﾓﾊ Average Complexity per File", f"{avg_complexity:.1f}"),
            ("ðﾟﾓﾏ Average Lines per Function", f"{lines_per_function:.1f}"),
            ("ðﾟﾎﾯ Functions per File", f"{stats['totals']['functions'] / max(stats['totals']['files'], 1):.1f}")
        ]

        for label, value in complexity_stats:
            stat_frame = tk.Frame(complexity_content, bg="#2d2d30", relief=tk.RAISED, bd=1)
            stat_frame.pack(fill=tk.X, pady=2)
            
            tk.Label(stat_frame, text=f"{label}: {value}", font=("JetBrains Mono", 9), 
                    fg="#cccccc", bg="#2d2d30").pack(anchor="w", padx=10, pady=5)

    def create_dependencies_section(self, stats):
        """Create the dependencies section"""
        deps_frame = tk.LabelFrame(
            self.overview_content_frame, text="ðﾟﾓﾦ Dependencies & Includes", 
            font=("JetBrains Mono", 12, "bold"), fg="#9C27B0", bg="#1e1e1e"
        )
        deps_frame.pack(fill=tk.X, padx=10, pady=10)

        deps_content = tk.Frame(deps_frame, bg="#1e1e1e")
        deps_content.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(deps_content, text=f"ðﾟﾓﾊ Total unique includes: {len(stats['dependencies'])}", 
                font=("JetBrains Mono", 10, "bold"), fg="#cccccc", bg="#1e1e1e").pack(anchor="w")

        # Group dependencies by type
        system_deps = [dep for dep in stats['dependencies'] if not dep.endswith('.h') and not dep.endswith('.hpp')]
        local_deps = [dep for dep in stats['dependencies'] if dep.endswith('.h') or dep.endswith('.hpp')]

        if system_deps:
            tk.Label(deps_content, text="ðﾟﾔﾧ System/Standard Libraries:", 
                    font=("JetBrains Mono", 9, "bold"), fg="#4CAF50", bg="#1e1e1e").pack(anchor="w", pady=(10, 5))
            
            deps_text = ", ".join(sorted(system_deps)[:20])  # Show first 20
            if len(system_deps) > 20:
                deps_text += f"... and {len(system_deps) - 20} more"
            
            tk.Label(deps_content, text=deps_text, font=("JetBrains Mono", 8), 
                    fg="#888888", bg="#1e1e1e", wraplength=800).pack(anchor="w", padx=20)

        if local_deps:
            tk.Label(deps_content, text="ðﾟﾓﾁ Local Headers:", 
                    font=("JetBrains Mono", 9, "bold"), fg="#2196F3", bg="#1e1e1e").pack(anchor="w", pady=(10, 5))
            
            local_text = ", ".join(sorted(local_deps))
            tk.Label(deps_content, text=local_text, font=("JetBrains Mono", 8), 
                    fg="#888888", bg="#1e1e1e", wraplength=800).pack(anchor="w", padx=20)

    def create_build_info_section(self, stats):
        """Create the build information section"""
        build_frame = tk.LabelFrame(
            self.overview_content_frame, text="ðﾟﾔﾨ Build Information", 
            font=("JetBrains Mono", 12, "bold"), fg="#FF6F00", bg="#1e1e1e"
        )
        build_frame.pack(fill=tk.X, padx=10, pady=10)

        build_content = tk.Frame(build_frame, bg="#1e1e1e")
        build_content.pack(fill=tk.X, padx=10, pady=10)

        build_info = stats['build_info']

        if build_info['makefile']:
            makefile_info = build_info['makefile']
            tk.Label(build_content, text=f"ðﾟﾓﾄ Makefile: {makefile_info['name']} ({makefile_info['size']} bytes, modified: {makefile_info['modified']})", 
                    font=("JetBrains Mono", 9), fg="#4CAF50", bg="#1e1e1e").pack(anchor="w")
        else:
            tk.Label(build_content, text="❌ No Makefile found", 
                    font=("JetBrains Mono", 9), fg="#f44336", bg="#1e1e1e").pack(anchor="w")

        if build_info['cmake']:
            cmake_info = build_info['cmake']
            tk.Label(build_content, text=f"ðﾟﾏﾗ️ CMakeLists.txt: {cmake_info['size']} bytes, modified: {cmake_info['modified']}", 
                    font=("JetBrains Mono", 9), fg="#4CAF50", bg="#1e1e1e").pack(anchor="w")

        if build_info['executable']:
            exe_info = build_info['executable']
            tk.Label(build_content, text=f"⚙️ Executable: main.exe ({exe_info['size']} bytes, modified: {exe_info['modified']})", 
                    font=("JetBrains Mono", 9), fg="#4CAF50", bg="#1e1e1e").pack(anchor="w")
        else:
            tk.Label(build_content, text="❌ No main.exe found", 
                    font=("JetBrains Mono", 9), fg="#f44336", bg="#1e1e1e").pack(anchor="w")

    def create_detailed_files_section(self, stats):
        """Create the detailed files section"""
        files_frame = tk.LabelFrame(
            self.overview_content_frame, text="ðﾟﾓﾋ Largest Files by Code Lines", 
            font=("JetBrains Mono", 12, "bold"), fg="#607D8B", bg="#1e1e1e"
        )
        files_frame.pack(fill=tk.X, padx=10, pady=10)

        files_content = tk.Frame(files_frame, bg="#1e1e1e")
        files_content.pack(fill=tk.X, padx=10, pady=10)

        # Create table header
        header_frame = tk.Frame(files_content, bg="#2d2d30")
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        tk.Label(header_frame, text="File", font=("JetBrains Mono", 9, "bold"), 
                fg="#cccccc", bg="#2d2d30", width=40).pack(side=tk.LEFT, padx=5)
        tk.Label(header_frame, text="Code Lines", font=("JetBrains Mono", 9, "bold"), 
                fg="#cccccc", bg="#2d2d30", width=15).pack(side=tk.LEFT, padx=5)
        tk.Label(header_frame, text="Functions", font=("JetBrains Mono", 9, "bold"), 
                fg="#cccccc", bg="#2d2d30", width=15).pack(side=tk.LEFT, padx=5)
        tk.Label(header_frame, text="Complexity", font=("JetBrains Mono", 9, "bold"), 
                fg="#cccccc", bg="#2d2d30", width=15).pack(side=tk.LEFT, padx=5)

        # Show top 10 largest files
        for i, (file_path, code_lines) in enumerate(stats['largest_files'][:10]):
            file_data = stats['files'][file_path]
            
            row_frame = tk.Frame(files_content, bg="#1e1e1e" if i % 2 == 0 else "#2a2a2a")
            row_frame.pack(fill=tk.X, pady=1)
            
            # Shorten file path for display
            display_path = os.path.basename(file_path)
            if len(display_path) > 35:
                display_path = display_path[:32] + "..."
            
            tk.Label(row_frame, text=display_path, font=("JetBrains Mono", 8), 
                    fg="#cccccc", bg=row_frame['bg'], width=40).pack(side=tk.LEFT, padx=5)
            tk.Label(row_frame, text=str(code_lines), font=("JetBrains Mono", 8), 
                    fg="#4CAF50", bg=row_frame['bg'], width=15).pack(side=tk.LEFT, padx=5)
            tk.Label(row_frame, text=str(file_data['functions']), font=("JetBrains Mono", 8), 
                    fg="#2196F3", bg=row_frame['bg'], width=15).pack(side=tk.LEFT, padx=5)
            tk.Label(row_frame, text=str(file_data['complexity_score']), font=("JetBrains Mono", 8), 
                    fg="#FF9800", bg=row_frame['bg'], width=15).pack(side=tk.LEFT, padx=5)

    def _display_analysis_error(self, error_msg):
        """Display analysis error"""
        for widget in self.overview_content_frame.winfo_children():
            widget.destroy()
        
        error_label = tk.Label(
            self.overview_content_frame, 
                        text=f"❌ Analysis failed: {error_msg}",
            font=("JetBrains Mono", 12), fg="#f44336", bg="#1e1e1e"
        )
        error_label.pack(expand=True, pady=50)
        
        self.analyze_btn.config(text="ðﾟﾔﾍ Analyze Project", state=tk.NORMAL)

    def export_stats(self):
        """Export project statistics to JSON file"""
        if not self.project_stats:
            messagebox.showwarning("Warning", "No analysis data available. Please analyze the project first.")
            return
        
        try:
            # Create a copy of stats for export (handle sets)
            export_stats = dict(self.project_stats)
            
            # Convert file stats to serializable format
            export_stats['files'] = {}
            for file_path, file_data in self.project_stats['files'].items():
                export_file_data = dict(file_data)
                export_file_data['dependencies'] = list(file_data['dependencies'])
                export_stats['files'][file_path] = export_file_data
            
            filename = f"project_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_stats, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Success", f"Statistics exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export statistics: {e}")

    def copy_overview(self):
        """Copy project overview to clipboard"""
        if not self.project_stats:
            messagebox.showwarning("Warning", "No analysis data available. Please analyze the project first.")
            return
        
        try:
            stats = self.project_stats
            overview_text = self.generate_overview_text(stats)
            pyperclip.copy(overview_text)
            messagebox.showinfo("Success", "Project overview copied to clipboard!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy overview: {e}")

    def generate_overview_text(self, stats):
        """Generate a text summary of the project statistics"""
        text = f"""
ðﾟﾓﾊ PROJECT OVERVIEW - {stats['timestamp']}
{'='*60}

ðﾟﾓﾁ PROJECT SUMMARY:
   Total Files: {stats['totals']['files']}
   Total Lines: {stats['totals']['total_lines']:,}
   Code Lines: {stats['totals']['code_lines']:,}
   Comment Lines: {stats['totals']['comment_lines']:,}
   Blank Lines: {stats['totals']['blank_lines']:,}
   Total Characters: {stats['totals']['total_chars']:,}
   Functions: {stats['totals']['functions']}
   Classes/Structs: {stats['totals']['classes']}
   Includes: {stats['totals']['includes']}

ðﾟﾓﾂ FILE TYPE BREAKDOWN:
"""
        for ext, data in stats['file_types'].items():
            text += f"   {ext}: {data['count']} files, {data['lines']:,} lines\n"

        text += f"""
ðﾟﾧﾮ COMPLEXITY ANALYSIS:
   Total Complexity Score: {sum(file_data['complexity_score'] for file_data in stats['files'].values())}
   Average Complexity per File: {sum(file_data['complexity_score'] for file_data in stats['files'].values()) / max(stats['totals']['files'], 1):.1f}
   Average Lines per Function: {stats['totals']['code_lines'] / max(stats['totals']['functions'], 1):.1f}

ðﾟﾓﾦ DEPENDENCIES:
   Total Unique Includes: {len(stats['dependencies'])}
   Dependencies: {', '.join(stats['dependencies'][:20])}
"""
        if len(stats['dependencies']) > 20:
            text += f"   ... and {len(stats['dependencies']) - 20} more\n"

        text += f"""
ðﾟﾔﾨ BUILD INFORMATION:
"""
        build_info = stats['build_info']
        if build_info['makefile']:
            text += f"   Makefile: {build_info['makefile']['name']} ({build_info['makefile']['size']} bytes)\n"
        else:
            text += "   Makefile: Not found\n"
        
        if build_info['executable']:
            text += f"   Executable: main.exe ({build_info['executable']['size']} bytes)\n"
        else:
            text += "   Executable: Not found\n"

        text += f"""
ðﾟﾓﾋ LARGEST FILES (by code lines):
"""
        for i, (file_path, code_lines) in enumerate(stats['largest_files'][:10], 1):
            file_data = stats['files'][file_path]
            filename = os.path.basename(file_path)
            text += f"   {i:2d}. {filename:<30} {code_lines:>6} lines, {file_data['functions']:>3} functions\n"

        return text

    def setup_files_tab(self):
        # === TOP BUTTONS ===
        button_frame = tk.Frame(self.files_frame, bg="#1e1e1e")
        button_frame.pack(fill=tk.X, padx=10, pady=(10, 0))

        self.refresh_btn = tk.Button(
            button_frame, text="ðﾟﾔﾄ Refresh Files", command=self.refresh_files,
            bg="#0E639C", fg="white", font=("JetBrains Mono", 10, "bold"), padx=10
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        self.copy_all_btn = tk.Button(
            button_frame, text="ðﾟﾓﾋ Copy All", command=self.copy_to_clipboard,
            bg="#007ACC", fg="white", font=("JetBrains Mono", 10, "bold"), padx=10
        )
        self.copy_all_btn.pack(side=tk.LEFT, padx=5)

        self.append_btn = tk.Button(
            button_frame, text="ðﾟﾓﾝ Append to Text View", command=self.append_to_textview,
            bg="#C586C0", fg="white", font=("JetBrains Mono", 10, "bold"), padx=10
        )
        self.append_btn.pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(
            button_frame, text="Ready", font=("JetBrains Mono", 9),
            fg="#CCCCCC", bg="#1e1e1e"
        )
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # === SCROLLABLE FRAME ===
        self.canvas = tk.Canvas(self.files_frame, bg="#1e1e1e", highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.files_frame, orient="vertical", command=self.canvas.yview)
        self.scroll_frame = tk.Frame(self.canvas, bg="#1e1e1e")

        self.scroll_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_make_tab(self):
        # Control panel
        make_control_frame = tk.Frame(self.make_frame, bg="#1e1e1e")
        make_control_frame.pack(fill=tk.X, padx=10, pady=10)

        # Make target input
        tk.Label(make_control_frame, text="Make Target:", font=("JetBrains Mono", 10), 
                fg="#cccccc", bg="#1e1e1e").pack(side=tk.LEFT, padx=(0, 5))
        
        self.make_target_entry = tk.Entry(make_control_frame, font=("JetBrains Mono", 10), 
                                        bg="#2d2d30", fg="#cccccc", insertbackground="white", width=15)
        self.make_target_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.make_target_entry.insert(0, "all")

        # Make buttons
        self.make_btn = tk.Button(
            make_control_frame, text="ðﾟﾔﾨ Make", command=self.run_make,
            bg="#FF6F00", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.make_btn.pack(side=tk.LEFT, padx=5)

        self.make_clean_btn = tk.Button(
            make_control_frame, text="ðﾟﾧﾹ Clean", command=self.run_make_clean,
            bg="#795548", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.make_clean_btn.pack(side=tk.LEFT, padx=5)

        self.make_rebuild_btn = tk.Button(
            make_control_frame, text="ðﾟﾔﾄ Rebuild", command=self.run_make_rebuild,
            bg="#E91E63", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.make_rebuild_btn.pack(side=tk.LEFT, padx=5)

        self.stop_make_btn = tk.Button(
            make_control_frame, text="⏹️ Stop", command=self.stop_make,
            bg="#f44336", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15, state=tk.DISABLED
        )
        self.stop_make_btn.pack(side=tk.LEFT, padx=5)

        # Quick make targets
        quick_targets_frame = tk.Frame(make_control_frame, bg="#1e1e1e")
        quick_targets_frame.pack(side=tk.LEFT, padx=(20, 0))

        quick_targets = [
            ("ðﾟﾓﾦ install", "install"),
            ("ðﾟﾧﾪ test", "test"),
            ("ðﾟﾓﾖ docs", "docs"),
            ("ðﾟﾔﾍ check", "check")
        ]

        for text, target in quick_targets:
            btn = tk.Button(
                quick_targets_frame, text=text, 
                command=lambda t=target: self.run_make_target(t),
                bg="#37474F", fg="white", font=("JetBrains Mono", 8), padx=8
            )
            btn.pack(side=tk.LEFT, padx=2)

        # Copy and clear buttons
        self.copy_make_btn = tk.Button(
            make_control_frame, text="ðﾟﾓﾋ Copy Output", command=self.copy_make_output,
            bg="#FF9800", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.copy_make_btn.pack(side=tk.RIGHT, padx=5)

        self.clear_make_btn = tk.Button(
            make_control_frame, text="ðﾟﾗﾑ️ Clear", command=self.clear_make_output,
            bg="#607D8B", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.clear_make_btn.pack(side=tk.RIGHT, padx=5)

        # Make status
        self.make_status = tk.Label(
            make_control_frame, text="Ready to build", font=("JetBrains Mono", 9),
            fg="#4CAF50", bg="#1e1e1e"
        )
        self.make_status.pack(side=tk.RIGHT, padx=10)

        # Makefile info frame
        makefile_info_frame = tk.Frame(self.make_frame, bg="#1e1e1e")
        makefile_info_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.makefile_status = tk.Label(
            makefile_info_frame, text="", font=("JetBrains Mono", 9),
            fg="#888888", bg="#1e1e1e"
        )
        self.makefile_status.pack(side=tk.LEFT)

        self.check_makefile_btn = tk.Button(
            makefile_info_frame, text="ðﾟﾔﾍ Check Makefile", command=self.check_makefile,
            bg="#3F51B5", fg="white", font=("JetBrains Mono", 9), padx=10
        )
        self.check_makefile_btn.pack(side=tk.RIGHT)

        # Make output area
        make_output_frame = tk.Frame(self.make_frame, bg="#1e1e1e")
        make_output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        tk.Label(make_output_frame, text="Make Output:", font=("JetBrains Mono", 10, "bold"), 
                fg="#cccccc", bg="#1e1e1e").pack(anchor="w", pady=(0, 5))

        self.make_output = scrolledtext.ScrolledText(
            make_output_frame,
            wrap=tk.WORD,
            font=("JetBrains Mono", 10),
            bg="#0d1117",
            fg="#79c0ff",
            insertbackground="white",
            relief=tk.FLAT,
            height=25
        )
        self.make_output.pack(fill=tk.BOTH, expand=True)

        # Check for Makefile on startup
        self.check_makefile()

    def setup_runner_tab(self):
        # Control panel
        control_frame = tk.Frame(self.runner_frame, bg="#1e1e1e")
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        # File input
        tk.Label(control_frame, text="Script File:", font=("JetBrains Mono", 10), 
                fg="#cccccc", bg="#1e1e1e").pack(side=tk.LEFT, padx=(0, 5))
        
        self.script_entry = tk.Entry(control_frame, font=("JetBrains Mono", 10), 
                                   bg="#2d2d30", fg="#cccccc", insertbackground="white", width=20)
        self.script_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.script_entry.insert(0, "hello.alt")

        # Buttons
        self.run_btn = tk.Button(
            control_frame, text="▶️ Run", command=self.run_executable,
            bg="#4CAF50", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.run_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(
            control_frame, text="⏹️ Stop", command=self.stop_executable,
            bg="#f44336", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15, state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.copy_output_btn = tk.Button(
            control_frame, text="ðﾟﾓﾋ Copy Output", command=self.copy_runner_output,
                        bg="#FF9800", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.copy_output_btn.pack(side=tk.LEFT, padx=5)

        self.clear_output_btn = tk.Button(
            control_frame, text="ðﾟﾗﾑ️ Clear", command=self.clear_runner_output,
            bg="#607D8B", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.clear_output_btn.pack(side=tk.LEFT, padx=5)

        # Status
        self.runner_status = tk.Label(
            control_frame, text="Ready to run", font=("JetBrains Mono", 9),
            fg="#4CAF50", bg="#1e1e1e"
        )
        self.runner_status.pack(side=tk.RIGHT, padx=10)

        # Output area
        output_frame = tk.Frame(self.runner_frame, bg="#1e1e1e")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        tk.Label(output_frame, text="Output:", font=("JetBrains Mono", 10, "bold"), 
                fg="#cccccc", bg="#1e1e1e").pack(anchor="w", pady=(0, 5))

        self.runner_output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            font=("JetBrains Mono", 10),
            bg="#0d1117",
            fg="#58a6ff",
            insertbackground="white",
            relief=tk.FLAT,
            height=25
        )
        self.runner_output.pack(fill=tk.BOTH, expand=True)

    def setup_debugger_tab(self):
        # Control panel
        debug_control_frame = tk.Frame(self.debugger_frame, bg="#1e1e1e")
        debug_control_frame.pack(fill=tk.X, padx=10, pady=10)

        # File input
        tk.Label(debug_control_frame, text="Script File:", font=("JetBrains Mono", 10), 
                fg="#cccccc", bg="#1e1e1e").pack(side=tk.LEFT, padx=(0, 5))
        
        self.debug_script_entry = tk.Entry(debug_control_frame, font=("JetBrains Mono", 10), 
                                         bg="#2d2d30", fg="#cccccc", insertbackground="white", width=20)
        self.debug_script_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.debug_script_entry.insert(0, "hello.alt")

        # Debug buttons
        self.start_gdb_btn = tk.Button(
            debug_control_frame, text="ðﾟﾐﾛ Start GDB", command=self.start_gdb,
            bg="#9C27B0", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.start_gdb_btn.pack(side=tk.LEFT, padx=5)

        self.stop_gdb_btn = tk.Button(
            debug_control_frame, text="⏹️ Stop GDB", command=self.stop_gdb,
            bg="#f44336", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15, state=tk.DISABLED
        )
        self.stop_gdb_btn.pack(side=tk.LEFT, padx=5)

        self.copy_debug_btn = tk.Button(
            debug_control_frame, text="ðﾟﾓﾋ Copy Debug", command=self.copy_debug_output,
            bg="#FF9800", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.copy_debug_btn.pack(side=tk.LEFT, padx=5)

        self.clear_debug_btn = tk.Button(
            debug_control_frame, text="ðﾟﾗﾑ️ Clear", command=self.clear_debug_output,
            bg="#607D8B", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.clear_debug_btn.pack(side=tk.LEFT, padx=5)

        # GDB Status
        self.gdb_status = tk.Label(
            debug_control_frame, text="GDB not running", font=("JetBrains Mono", 9),
            fg="#f44336", bg="#1e1e1e"
        )
        self.gdb_status.pack(side=tk.RIGHT, padx=10)

        # Command input frame
        cmd_frame = tk.Frame(self.debugger_frame, bg="#1e1e1e")
        cmd_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Label(cmd_frame, text="GDB Command:", font=("JetBrains Mono", 10), 
                fg="#cccccc", bg="#1e1e1e").pack(side=tk.LEFT, padx=(0, 5))

        self.gdb_command_entry = tk.Entry(cmd_frame, font=("JetBrains Mono", 10), 
                                        bg="#2d2d30", fg="#cccccc", insertbackground="white")
        self.gdb_command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.gdb_command_entry.bind('<Return>', self.send_gdb_command)

        self.send_cmd_btn = tk.Button(
            cmd_frame, text="➤ Send", command=self.send_gdb_command,
            bg="#2196F3", fg="white", font=("JetBrains Mono", 10, "bold"), padx=15
        )
        self.send_cmd_btn.pack(side=tk.RIGHT)

        # Quick commands
        quick_cmd_frame = tk.Frame(self.debugger_frame, bg="#1e1e1e")
        quick_cmd_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        quick_commands = [
            ("▶️ run", "run"),
            ("⏸️ break main", "break main"),
            ("➡️ next", "next"),
            ("⬇️ step", "step"),
            ("ðﾟﾓﾋ bt", "backtrace"),
            ("ðﾟﾓﾊ info locals", "info locals"),
            ("ðﾟﾔﾍ list", "list"),
            ("▶️ continue", "continue")
        ]

        for i, (text, cmd) in enumerate(quick_commands):
            btn = tk.Button(
                quick_cmd_frame, text=text, 
                command=lambda c=cmd: self.send_gdb_command_direct(c),
                bg="#37474F", fg="white", font=("JetBrains Mono", 8), padx=8
            )
            btn.pack(side=tk.LEFT, padx=2)

        # Debug output area
        debug_output_frame = tk.Frame(self.debugger_frame, bg="#1e1e1e")
        debug_output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        tk.Label(debug_output_frame, text="GDB Output:", font=("JetBrains Mono", 10, "bold"), 
                fg="#cccccc", bg="#1e1e1e").pack(anchor="w", pady=(0, 5))

        self.debug_output = scrolledtext.ScrolledText(
            debug_output_frame,
            wrap=tk.WORD,
            font=("JetBrains Mono", 10),
            bg="#0d1117",
            fg="#ff7b72",
            insertbackground="white",
            relief=tk.FLAT,
            height=20
        )
        self.debug_output.pack(fill=tk.BOTH, expand=True)

    # === MAKE METHODS ===
    def check_makefile(self):
        """Check for Makefile existence and show info"""
        makefiles = ["Makefile", "makefile", "GNUmakefile"]
        found_makefile = None
        
        for makefile in makefiles:
            if os.path.exists(makefile):
                found_makefile = makefile
                break
        
        if found_makefile:
            try:
                # Get file modification time
                mtime = os.path.getmtime(found_makefile)
                mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
                
                # Get file size
                size = os.path.getsize(found_makefile)
                
                self.makefile_status.config(
                    text=f"✅ Found: {found_makefile} ({size} bytes, modified: {mtime_str})",
                    fg="#4CAF50"
                )
                
                # Try to extract targets from Makefile
                self.extract_makefile_targets(found_makefile)
                
            except Exception as e:
                self.makefile_status.config(
                    text=f"⚠️ Found {found_makefile} but error reading: {e}",
                    fg="#FF9800"
                )
        else:
            self.makefile_status.config(
                text="❌ No Makefile found (Makefile, makefile, or GNUmakefile)",
                fg="#f44336"
            )

    def extract_makefile_targets(self, makefile_path):
        """Extract available targets from Makefile"""
        try:
            with open(makefile_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple regex to find targets (lines that start with word characters followed by :)
            targets = re.findall(r'^([a-zA-Z_][a-zA-Z0-9_-]*)\s*:', content, re.MULTILINE)
            
            if targets:
                # Update the make target entry with autocomplete-like behavior
                self.available_targets = targets
                self.make_output.insert(tk.END, f"ðﾟﾓﾋ Available targets: {', '.join(targets[:10])}")
                if len(targets) > 10:
                    self.make_output.insert(tk.END, f" ... and {len(targets) - 10} more\n")
                else:
                    self.make_output.insert(tk.END, "\n")
                
        except Exception as e:
            self.make_output.insert(tk.END, f"⚠️ Could not extract targets: {e}\n")

    def run_make(self):
        """Run make with specified target"""
        target = self.make_target_entry.get().strip()
        if not target:
            target = "all"
        
        self.run_make_target(target)

    def run_make_clean(self):
        """Run make clean"""
        self.run_make_target("clean")

    def run_make_rebuild(self):
        """Run make clean followed by make all"""
        self.make_output.insert(tk.END, "ðﾟﾔﾄ Starting rebuild process...\n")
        self.make_output.insert(tk.END, "=" * 50 + "\n")
        
        # First run clean, then all
        def rebuild_sequence():
            self.run_make_target("clean", callback=lambda: self.run_make_target("all"))
        
        threading.Thread(target=rebuild_sequence, daemon=True).start()

    def run_make_target(self, target, callback=None):
        """Run make with specific target"""
        if self.make_process and self.make_process.poll() is None:
            messagebox.showwarning("Warning", "Make is already running")
            return

        try:
            self.make_output.insert(tk.END, f"ðﾟﾔﾨ Running: make {target}\n")
            self.make_output.insert(tk.END, "=" * 50 + "\n")
            
            # Check if make command exists
            try:
                subprocess.run(["make", "--version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                self.make_output.insert(tk.END, "❌ Error: 'make' command not found. Please install make.\n")
                self.make_status.config(text="Make not found", fg="#f44336")
                return
            
            self.make_process = subprocess.Popen(
                ["make", target],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.make_btn.config(state=tk.DISABLED)
            self.make_clean_btn.config(state=tk.DISABLED)
            self.make_rebuild_btn.config(state=tk.DISABLED)
            self.stop_make_btn.config(state=tk.NORMAL)
            self.make_status.config(text=f"Building {target}...", fg="#FF9800")
            
            # Start thread to read output
            threading.Thread(target=lambda: self.read_make_output(callback), daemon=True).start()
            
        except Exception as e:
            self.make_output.insert(tk.END, f"❌ Failed to start make: {e}\n")
            self.make_status.config(text="Error", fg="#f44336")

    def read_make_output(self, callback=None):
        """Read make process output"""
        try:
            while self.make_process and self.make_process.poll() is None:
                output = self.make_process.stdout.readline()
                if output:
                    self.root.after(0, lambda text=output: self.append_make_output(text))
                time.sleep(0.01)
            
            # Read any remaining output
            if self.make_process:
                remaining_output = self.make_process.stdout.read()
                if remaining_output:
                    self.root.after(0, lambda text=remaining_output: self.append_make_output(text))
                
                return_code = self.make_process.returncode
                self.root.after(0, lambda: self.make_process_finished(return_code, callback))
                
        except Exception as e:
            self.root.after(0, lambda: self.append_make_output(f"\nError reading make output: {e}\n"))

    def append_make_output(self, text):
        """Append text to make output with syntax highlighting"""
        self.make_output.insert(tk.END, text)
        
        # Simple syntax highlighting for make output
        current_line = self.make_output.index(tk.INSERT).split('.')[0]
        line_start = f"{current_line}.0"
        line_end = f"{current_line}.end"
        
        line_text = text.lower()
        if "error" in line_text:
            self.make_output.tag_add("error", line_start, line_end)
            self.make_output.tag_config("error", foreground="#ff7b72")
        elif "warning" in line_text:
            self.make_output.tag_add("warning", line_start, line_end)
            self.make_output.tag_config("warning", foreground="#f0883e")
        elif line_text.startswith("make"):
            self.make_output.tag_add("make_cmd", line_start, line_end)
            self.make_output.tag_config("make_cmd", foreground="#79c0ff")
        
        self.make_output.see(tk.END)
        self.make_output.update()

        def make_process_finished(self, return_code, callback=None):
            """Handle make process completion"""
        self.make_output.insert(tk.END, f"\n{'='*50}\n")
        if return_code == 0:
            self.make_output.insert(tk.END, "✅ Make completed successfully\n")
            self.make_status.config(text="Build successful", fg="#4CAF50")
        else:
            self.make_output.insert(tk.END, f"❌ Make failed with exit code {return_code}\n")
            self.make_status.config(text=f"Build failed ({return_code})", fg="#f44336")
        
        self.make_btn.config(state=tk.NORMAL)
        self.make_clean_btn.config(state=tk.NORMAL)
        self.make_rebuild_btn.config(state=tk.NORMAL)
        self.stop_make_btn.config(state=tk.DISABLED)
        self.make_output.see(tk.END)
        
        # Execute callback if provided (for rebuild sequence)
        if callback and return_code == 0:
            self.root.after(1000, callback)  # Wait 1 second before next command

    def stop_make(self):
        """Stop the make process"""
        if self.make_process and self.make_process.poll() is None:
            try:
                self.make_process.terminate()
                self.make_output.insert(tk.END, "\n⏹️ Make process terminated by user\n")
                self.make_status.config(text="Stopped", fg="#f44336")
            except Exception as e:
                self.make_output.insert(tk.END, f"\nError stopping make: {e}\n")
        
        self.make_btn.config(state=tk.NORMAL)
        self.make_clean_btn.config(state=tk.NORMAL)
        self.make_rebuild_btn.config(state=tk.NORMAL)
        self.stop_make_btn.config(state=tk.DISABLED)

    def copy_make_output(self):
        """Copy make output to clipboard"""
        content = self.make_output.get(1.0, tk.END).strip()
        if content:
            try:
                pyperclip.copy(content)
                self.make_status.config(text="Output copied!", fg="#4CAF50")
                self.root.after(2000, lambda: self.make_status.config(text="Ready to build", fg="#4CAF50"))
            except Exception as e:
                messagebox.showerror("Error", f"Copy failed: {e}")

    def clear_make_output(self):
        """Clear make output"""
        self.make_output.delete(1.0, tk.END)
        self.make_status.config(text="Output cleared", fg="#607D8B")
        self.root.after(2000, lambda: self.make_status.config(text="Ready to build", fg="#4CAF50"))

    # === RUNNER METHODS ===
    def run_executable(self):
        script_file = self.script_entry.get().strip()
        if not script_file:
            messagebox.showwarning("Warning", "Please enter a script file name")
            return

        if not os.path.exists("main.exe"):
            messagebox.showerror("Error", "main.exe not found in current directory")
            return

        if self.running_process and self.running_process.poll() is None:
            messagebox.showwarning("Warning", "Process is already running")
            return

        try:
            self.runner_output.delete(1.0, tk.END)
            self.runner_output.insert(tk.END, f"ðﾟﾚﾀ Starting: ./main.exe {script_file}\n")
            self.runner_output.insert(tk.END, "=" * 50 + "\n")
            
            self.running_process = subprocess.Popen(
                ["./main.exe", script_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.run_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.runner_status.config(text="Running...", fg="#FF9800")
            
            # Start thread to read output
            threading.Thread(target=self.read_process_output, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start process: {e}")
            self.runner_status.config(text="Error", fg="#f44336")

    def read_process_output(self):
        try:
            while self.running_process and self.running_process.poll() is None:
                output = self.running_process.stdout.readline()
                if output:
                    self.root.after(0, lambda: self.append_runner_output(output))
                time.sleep(0.01)
            
            # Read any remaining output
            if self.running_process:
                remaining_output = self.running_process.stdout.read()
                if remaining_output:
                    self.root.after(0, lambda: self.append_runner_output(remaining_output))
                
                return_code = self.running_process.returncode
                self.root.after(0, lambda: self.process_finished(return_code))
                
        except Exception as e:
            self.root.after(0, lambda: self.append_runner_output(f"\nError reading output: {e}\n"))

    def append_runner_output(self, text):
        self.runner_output.insert(tk.END, text)
        self.runner_output.see(tk.END)
        self.runner_output.update()

    def process_finished(self, return_code):
        self.runner_output.insert(tk.END, f"\n{'='*50}\n")
        if return_code == 0:
            self.runner_output.insert(tk.END, "✅ Process completed successfully\n")
            self.runner_status.config(text="Completed", fg="#4CAF50")
        else:
            self.runner_output.insert(tk.END, f"❌ Process exited with code {return_code}\n")
            self.runner_status.config(text=f"Exit code: {return_code}", fg="#f44336")
        
        self.run_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.runner_output.see(tk.END)

    def stop_executable(self):
        if self.running_process and self.running_process.poll() is None:
            try:
                self.running_process.terminate()
                self.runner_output.insert(tk.END, "\n⏹️ Process terminated by user\n")
                self.runner_status.config(text="Stopped", fg="#f44336")
            except Exception as e:
                self.runner_output.insert(tk.END, f"\nError stopping process: {e}\n")
        
        self.run_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def copy_runner_output(self):
        content = self.runner_output.get(1.0, tk.END).strip()
        if content:
            try:
                pyperclip.copy(content)
                self.runner_status.config(text="Output copied!", fg="#4CAF50")
                self.root.after(2000, lambda: self.runner_status.config(text="Ready to run", fg="#4CAF50"))
            except Exception as e:
                messagebox.showerror("Error", f"Copy failed: {e}")

    def clear_runner_output(self):
        self.runner_output.delete(1.0, tk.END)
        self.runner_status.config(text="Output cleared", fg="#607D8B")
        self.root.after(2000, lambda: self.runner_status.config(text="Ready to run", fg="#4CAF50"))

    # === GDB DEBUGGER METHODS ===
    def start_gdb(self):
        script_file = self.debug_script_entry.get().strip()
        if not script_file:
            messagebox.showwarning("Warning", "Please enter a script file name")
            return

        if not os.path.exists("main.exe"):
            messagebox.showerror("Error", "main.exe not found in current directory")
            return

        if self.gdb_process and self.gdb_process.poll() is None:
            messagebox.showwarning("Warning", "GDB is already running")
            return

        try:
            self.debug_output.delete(1.0, tk.END)
            self.debug_output.insert(tk.END, f"ðﾟﾐﾛ Starting GDB with: main.exe {script_file}\n")
            self.debug_output.insert(tk.END, "=" * 50 + "\n")
            
            # Start GDB with the executable and script arguments
            gdb_command = ["gdb", "--interpreter=mi", "--args", "./main.exe", script_file]
            
            self.gdb_process = subprocess.Popen(
                gdb_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.start_gdb_btn.config(state=tk.DISABLED)
            self.stop_gdb_btn.config(state=tk.NORMAL)
            self.send_cmd_btn.config(state=tk.NORMAL)
            self.gdb_command_entry.config(state=tk.NORMAL)
            self.gdb_status.config(text="GDB Running", fg="#4CAF50")
            
            # Start thread to read GDB output
            threading.Thread(target=self.read_gdb_output, daemon=True).start()
            
            # Send initial setup commands
            time.sleep(0.5)  # Give GDB time to start
            self.send_gdb_command_direct("set args " + script_file)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start GDB: {e}")
            self.gdb_status.config(text="GDB Error", fg="#f44336")

    def read_gdb_output(self):
        try:
            while self.gdb_process and self.gdb_process.poll() is None:
                output = self.gdb_process.stdout.readline()
                if output:
                    # Filter out some GDB MI noise for cleaner output
                    if not output.startswith('(gdb)') and not output.startswith('=') and output.strip():
                        self.root.after(0, lambda text=output: self.append_debug_output(text))
                time.sleep(0.01)
            
            # GDB process ended
            self.root.after(0, self.gdb_process_ended)
                
        except Exception as e:
            self.root.after(0, lambda: self.append_debug_output(f"\nError reading GDB output: {e}\n"))

    def append_debug_output(self, text):
        self.debug_output.insert(tk.END, text)
        self.debug_output.see(tk.END)
        self.debug_output.update()

    def gdb_process_ended(self):
        self.debug_output.insert(tk.END, "\nðﾟﾐﾛ GDB session ended\n")
        self.start_gdb_btn.config(state=tk.NORMAL)
        self.stop_gdb_btn.config(state=tk.DISABLED)
        self.send_cmd_btn.config(state=tk.DISABLED)
        self.gdb_command_entry.config(state=tk.DISABLED)
        self.gdb_status.config(text="GDB not running", fg="#f44336")

    def send_gdb_command(self, event=None):
        command = self.gdb_command_entry.get().strip()
        if command:
            self.send_gdb_command_direct(command)
            self.gdb_command_entry.delete(0, tk.END)

    def send_gdb_command_direct(self, command):
        if self.gdb_process and self.gdb_process.poll() is None:
            try:
                self.debug_output.insert(tk.END, f"\n(gdb) {command}\n")
                self.gdb_process.stdin.write(command + "\n")
                self.gdb_process.stdin.flush()
                self.debug_output.see(tk.END)
            except Exception as e:
                self.debug_output.insert(tk.END, f"Error sending command: {e}\n")

    def stop_gdb(self):
        if self.gdb_process and self.gdb_process.poll() is None:
            try:
                self.gdb_process.stdin.write("quit\n")
                self.gdb_process.stdin.flush()
                time.sleep(0.5)
                if self.gdb_process.poll() is None:
                    self.gdb_process.terminate()
                self.debug_output.insert(tk.END, "\n⏹️ GDB terminated\n")
            except Exception as e:
                self.debug_output.insert(tk.END, f"\nError stopping GDB: {e}\n")
        
        self.gdb_process_ended()

    def copy_debug_output(self):
        content = self.debug_output.get(1.0, tk.END).strip()
        if content:
            try:
                pyperclip.copy(content)
                self.gdb_status.config(text="Debug output copied!", fg="#4CAF50")
                self.root.after(2000, lambda: self.gdb_status.config(
                    text="GDB Running" if self.gdb_process and self.gdb_process.poll() is None 
                    else "GDB not running", 
                    fg="#4CAF50" if self.gdb_process and self.gdb_process.poll() is None else "#f44336"
                ))
            except Exception as e:
                messagebox.showerror("Error", f"Copy failed: {e}")

    def clear_debug_output(self):
        self.debug_output.delete(1.0, tk.END)
        self.gdb_status.config(text="Debug output cleared", fg="#607D8B")
        self.root.after(2000, lambda: self.gdb_status.config(
            text="GDB Running" if self.gdb_process and self.gdb_process.poll() is None 
            else "GDB not running", 
            fg="#4CAF50" if self.gdb_process and self.gdb_process.poll() is None else "#f44336"
        ))

    # === ORIGINAL FILE METHODS ===
    def clear_text_boxes(self):
        for frame in self.text_boxes:
            frame.destroy()
        self.text_boxes = []

    def create_text_box(self, parent, content, row, col):
        container = tk.Frame(parent, bg="#1e1e1e", padx=5, pady=5)
        container.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        parent.grid_columnconfigure(col, weight=1)

        # Add character count display
        char_count = len(content)
        header_frame = tk.Frame(container, bg="#1e1e1e")
        header_frame.pack(fill=tk.X, pady=(0, 2))

        char_label = tk.Label(
            header_frame, text=f"Characters: {char_count:,}",
            font=("JetBrains Mono", 8), fg="#888888", bg="#1e1e1e"
        )
        char_label.pack(side=tk.LEFT)

        copy_btn = tk.Button(
            header_frame, text="ðﾟﾓﾋ Copy", bg="#3C3C3C", fg="white",
            font=("JetBrains Mono", 9, "bold")
        )
        copy_btn.pack(side=tk.RIGHT)

        text_box = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            font=("JetBrains Mono", 10),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white",
            relief=tk.FLAT,
            height=20
        )
        text_box.pack(fill=tk.BOTH, expand=True)
        text_box.insert(1.0, content)

        copy_btn.config(command=lambda: self.copy_single_box(text_box, copy_btn))

        self.apply_syntax_highlighting(text_box)
        self.text_boxes.append(container)

    def apply_syntax_highlighting(self, text_widget):
        code = text_widget.get(1.0, tk.END)

        def apply_tag(pattern, tag, color):
            for match in re.finditer(pattern, code, re.MULTILINE):
                start = f"1.0 + {match.start()} chars"
                end = f"1.0 + {match.end()} chars"
                text_widget.tag_add(tag, start, end)

            text_widget.tag_config(tag, foreground=color)

        apply_tag(r"\b(class|struct|int|char|float|double|if|else|for|while|return|void|include|namespace|public|private|protected|switch|case|break|continue)\b", "keyword", "#569CD6")
        apply_tag(r"\b(std|size_t|string|vector|map|unordered_map|bool)\b", "type", "#4EC9B0")
        apply_tag(r'"[^"\n]*"', "string", "#CE9178")
        apply_tag(r"//.*?$", "comment", "#6A9955")
        apply_tag(r"/\*[\s\S]*?\*/", "comment_multiline", "#6A9955")

    def get_c_h_files_content(self):
        directories = ["", "helpers", "packages"]
        all_contents = []
        file_count = 0

        for directory in directories:
            path = os.path.join(os.getcwd(), directory)
            if not os.path.exists(path):
                continue

            for filename in os.listdir(path):
                if filename.endswith(('.c')):
                    full_path = os.path.join(path, filename)
                    if os.path.isfile(full_path):
                        try:
                            with open(full_path, 'r', encoding='utf-8') as file:
                                content = file.read()
                            header = f"\n{'='*50}\n{os.path.join(directory, filename)}\n{'='*50}\n"
                            all_contents.append(header + content)
                            file_count += 1
                        except Exception as e:
                            all_contents.append(f"\nERROR reading {filename}: {e}\n")

        return all_contents, file_count

    def split_large_content(self, content, max_chars):
        """Split content that exceeds max_chars into smaller chunks at logical breakpoints."""
        if len(content) <= max_chars:
            return [content]
        
        chunks = []
        current_pos = 0
        
        while current_pos < len(content):
            # Calculate the end position for this chunk
            end_pos = min(current_pos + max_chars, len(content))
            
            # If we're not at the end of the content, try to find a good break point
            if end_pos < len(content):
                # Look for good break points (in order of preference)
                break_points = [
                    content.rfind('\n\n', current_pos, end_pos),  # Double newline
                    content.rfind('\n}', current_pos, end_pos),   # End of function/class
                    content.rfind(';\n', current_pos, end_pos),   # End of statement
                    content.rfind('\n', current_pos, end_pos),    # Any newline
                ]
                
                # Use the best available break point
                for break_point in break_points:
                    if break_point > current_pos:
                        end_pos = break_point + 1
                        break
            
            chunk = content[current_pos:end_pos]
            if chunk.strip():  # Only add non-empty chunks
                chunks.append(chunk)
            
            current_pos = end_pos
        
        return chunks

    def refresh_files(self):
        self.status_label.config(text="Refreshing...")
        self.root.update()

        self.clear_text_boxes()
        content_list, file_count = self.get_c_h_files_content()

        if not content_list:
            self.create_text_box(self.scroll_frame, "No .cpp or .hpp files found.", 0, 0)
            self.status_label.config(text="No files found")
            return

        row = col = 0
        current_chunk = ""
        current_length = 0

        for file_content in content_list:
            file_length = len(file_content)

            # If this single file exceeds the limit, split it
            if file_length > MAX_CHARACTERS:
                # First, create a box for any accumulated content
                if current_chunk:
                    self.create_text_box(self.scroll_frame, current_chunk, row, col)
                    col = (col + 1) % 2
                    if col == 0:
                        row += 1
                    current_chunk = ""
                    current_length = 0
                
                # Split the large file into smaller chunks
                file_chunks = self.split_large_content(file_content, MAX_CHARACTERS)
                for chunk in file_chunks:
                    self.create_text_box(self.scroll_frame, chunk, row, col)
                    col = (col + 1) % 2
                    if col == 0:
                        row += 1
                        
            # If adding this file would exceed the limit, create a new box
            elif current_length + file_length > MAX_CHARACTERS:
                if current_chunk:
                    self.create_text_box(self.scroll_frame, current_chunk, row, col)
                    col = (col + 1) % 2
                    if col == 0:
                        row += 1
                current_chunk = file_content
                current_length = file_length
            else:
                # Add to current chunk
                current_chunk += file_content
                current_length += file_length

        # Create final box if there's remaining content
        if current_chunk:
            self.create_text_box(self.scroll_frame, current_chunk, row, col)

        total_boxes = len(self.text_boxes)
        self.status_label.config(text=f"Loaded {file_count} files into {total_boxes} boxes")

    def copy_single_box(self, text_widget, button):
        content = text_widget.get(1.0, tk.END).strip()
        if content:
            try:
                pyperclip.copy(content)
                original_text = button["text"]
                button.config(text="✔ Copied!", bg="#007ACC")
                self.root.after(2000, lambda: button.config(text=original_text, bg="#3C3C3C"))
                char_count = len(content)
                self.status_label.config(text=f"Copied {char_count:,} characters to clipboard")
            except Exception as e:
                messagebox.showerror("Error", f"Copy failed: {e}")
        else:
            messagebox.showwarning("Warning", "This box is empty")

    def copy_to_clipboard(self):
        content = ""
        for box_frame in self.text_boxes:
            for widget in box_frame.winfo_children():
                if isinstance(widget, scrolledtext.ScrolledText):
                    content += widget.get(1.0, tk.END)

        content = content.strip()
        if content:
            try:
                pyperclip.copy(content)
                char_count = len(content)
                self.status_label.config(text=f"Copied ALL ({char_count:,} chars) to clipboard!")
                self.root.after(3000, lambda: self.status_label.config(text="Ready"))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy: {e}")
        else:
            messagebox.showwarning("Warning", "Nothing to copy")

    def append_to_textview(self):
        content = ""
        for box_frame in self.text_boxes:
            for widget in box_frame.winfo_children():
                if isinstance(widget, scrolledtext.ScrolledText):
                    content += widget.get(1.0, tk.END)
        content = content.strip()

        if not content:
            messagebox.showwarning("Warning", "No content to append")
            return

        countdown_window = tk.Toplevel(self.root)
        countdown_window.title("Countdown")
        countdown_window.geometry("300x100")
        countdown_window.configure(bg="#1e1e1e")
        countdown_label = tk.Label(
            countdown_window, text="Click on target window...",
            font=("JetBrains Mono", 14), bg="#1e1e1e", fg="#d4d4d4"
        )
        countdown_label.pack(expand=True)

        def countdown_and_type():
            for i in range(5, 0, -1):
                countdown_label.config(text=f"Typing in {i}...")
                time.sleep(1)
            countdown_window.destroy()
            self.status_label.config(text="Typing...")
            self.root.update()

            try:
                pyautogui.typewrite(content, interval=0.001)
                char_count = len(content)
                self.status_label.config(text=f"Typed {char_count:,} characters!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to type: {e}")
                self.status_label.config(text="Error")

        threading.Thread(target=countdown_and_type, daemon=True).start()

    def __del__(self):
        # Cleanup processes when the application is closed
        if hasattr(self, 'running_process') and self.running_process and self.running_process.poll() is None:
            try:
                self.running_process.terminate()
            except:
                pass
        
        if hasattr(self, 'gdb_process') and self.gdb_process and self.gdb_process.poll() is None:
            try:
                self.gdb_process.stdin.write("quit\n")
                self.gdb_process.stdin.flush()
                time.sleep(0.5)
                self.gdb_process.terminate()
            except:
                pass
        
        if hasattr(self, 'make_process') and self.make_process and self.make_process.poll() is None:
            try:
                self.make_process.terminate()
            except:
                pass


def main():
    root = tk.Tk()
    
    # Handle window closing to cleanup processes
    def on_closing():
        try:
            if hasattr(app, 'running_process') and app.running_process and app.running_process.poll() is None:
                app.running_process.terminate()
            if hasattr(app, 'gdb_process') and app.gdb_process and app.gdb_process.poll() is None:
                app.gdb_process.stdin.write("quit\n")
                app.gdb_process.stdin.flush()
                time.sleep(0.5)
                app.gdb_process.terminate()
            if hasattr(app, 'make_process') and app.make_process and app.make_process.poll() is None:
                app.make_process.terminate()
        except:
            pass
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    app = CHeaderDumper(root)
    root.mainloop()

if __name__ == "__main__":
    main()
