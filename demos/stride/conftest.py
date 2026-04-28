import sys
import os

# Ensure the project root (demos/stride) is on sys.path so that
# `from app.src import missions` resolves correctly regardless of
# which directory pytest is invoked from.
sys.path.insert(0, os.path.dirname(__file__))
