"""
ZAS Splash Screen - Loading animation before main GUI
"""

import tkinter as tk
import threading
import time


class SplashScreen:
    """Animated splash screen with loading progress."""
    
    def __init__(self, on_complete=None):
        self.on_complete = on_complete
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.configure(bg="#0a0d0b")
        
        # Center on screen
        w, h = 400, 300
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        
        # Content
        frame = tk.Frame(self.root, bg="#0a0d0b")
        frame.pack(fill="both", expand=True)
        
        # Accent line top
        tk.Frame(frame, height=3, bg="#c9ff45").pack(fill="x")
        
        # Logo area
        logo_frame = tk.Frame(frame, bg="#0a0d0b")
        logo_frame.pack(expand=True)
        
        # ZAS text
        tk.Label(logo_frame, text="ZAS", font=("Consolas", 36, "bold"),
                 fg="#c9ff45", bg="#0a0d0b").pack()
        tk.Label(logo_frame, text="v5.1", font=("Consolas", 14),
                 fg="#8b949e", bg="#0a0d0b").pack()
        
        # Loading text
        self.loading_label = tk.Label(frame, text="Loading modules...", 
                                       font=("Consolas", 10), fg="#8b949e", bg="#0a0d0b")
        self.loading_label.pack(pady=(0, 10))
        
        # Progress bar container
        bar_frame = tk.Frame(frame, bg="#21262d", height=4)
        bar_frame.pack(fill="x", padx=40, pady=(0, 20))
        bar_frame.pack_propagate(False)
        
        # Progress bar fill
        self.bar_fill = tk.Frame(bar_frame, bg="#c9ff45", width=0)
        self.bar_fill.pack(side="left", fill="y")
        
        # Accent line bottom
        tk.Frame(frame, height=3, bg="#c9ff45").pack(fill="x")
        
        self.progress = 0
        self.running = True
        
    def update_progress(self, text, percent):
        """Update loading text and progress bar."""
        self.loading_label.configure(text=text)
        self.progress = percent
        # Calculate bar width (max ~320px for 400px window with 40px padding each side)
        bar_width = int(percent / 100 * 320)
        self.bar_fill.configure(width=bar_width)
        self.root.update_idletasks()
    
    def start(self, load_func):
        """Start loading in background thread."""
        def _load():
            try:
                load_func(self.update_progress)
            except Exception as e:
                self.update_progress(f"Error: {e}", 100)
            finally:
                time.sleep(0.5)
                self.running = False
                self.root.after(0, self._close)
        
        threading.Thread(target=_load, daemon=True).start()
        self.root.mainloop()
    
    def _close(self):
        """Close splash and call completion handler."""
        self.root.destroy()
        if self.on_complete:
            self.on_complete()
