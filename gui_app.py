#!/usr/bin/env python3
"""
gui_app.py - production GUI entry point.

    python gui_app.py

Protect / Verify / Attack simulation, all driven by
a2_crypto.protect()/verify() over the real image and audio codecs. This is
the GUI the spec requires (FR1/FR2 input, FR5/FR6 embedding, FR8 extraction,
FR10 verdicts); a2_debug_gui.py is a separate developer test bench.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import App

if __name__ == "__main__":
    App().mainloop()
