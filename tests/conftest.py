import sys
import os

# Add the project's root directory to the Python path
# This allows tests to import modules from the src directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
