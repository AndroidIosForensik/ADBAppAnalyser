"""Einstiegspunkt fuer den PyInstaller-Build der appanalyse-CLI."""
import multiprocessing
from appanalyse.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
