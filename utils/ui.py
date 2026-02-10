import sys
from .colors import Colors, colorize

class ProgressBar:
    """A simple CLI progress bar."""
    def __init__(self, total: int, prefix: str = 'Scanning', length: int = 40):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0

    def update(self, current: int):
        self.current = current
        self._print_bar()

    def increment(self):
        self.current += 1
        self._print_bar()

    def finish(self):
        self.current = self.total
        self._print_bar()
        sys.stdout.write('\n')
        sys.stdout.flush()

    def _print_bar(self):
        percent = 100 * (self.current / float(self.total))
        filled_length = int(self.length * self.current // self.total)
        bar = '█' * filled_length + '-' * (self.length - filled_length)
        
        # Colorize the bar (Green if complete, Cyan if in progress)
        color = Colors.GREEN if self.current >= self.total else Colors.CYAN
        colored_bar = colorize(bar, color)
        
        sys.stdout.write(f'\r{self.prefix} |{colored_bar}| {percent:.1f}% ({self.current}/{self.total})')
        sys.stdout.flush()

def print_table_header():
    header = f"{'PORT':<8} {'STATUS':<10} {'SERVICE':<15} {'VERSION':<25} {'OS':<15}"
    separator = "-" * 80
    print(colorize(header, Colors.BOLD + Colors.WHITE))
    print(colorize(separator, Colors.BLUE))
