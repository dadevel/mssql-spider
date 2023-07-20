from argparse import RawTextHelpFormatter
import os
import shutil

# in seconds
TIMEOUT = 10

# scale threads with cpu cores
THREAD_COUNT = max((os.cpu_count() or 1) * 4, 32)

# scale width of help text with terminal width
HELP_FORMATTER = lambda prog: RawTextHelpFormatter(prog, max_help_position=round(shutil.get_terminal_size().columns / 2))
