from utils import helper
import os

# top-level constant whose value is a call — must attribute to the FILE, not GREETING
GREETING = helper()

def main():
    helper()
    print("hello")

class App:
    def run(self):
        main()
