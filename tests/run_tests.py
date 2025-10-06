#!/usr/bin/env python3
import os
import sys
import argparse
import unittest

def main():
    parser = argparse.ArgumentParser(description="Run protocol tests.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Target host for tests (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3239,
                        help="Target port for tests (default: 3239)")
    # Parse our custom arguments and any remaining unittest args.
    args, remaining_args = parser.parse_known_args()

    # Set environment variables so that test files pick up host and port.
    os.environ["ANGRYUEFI_HOST"] = args.host
    os.environ["ANGRYUEFI_PORT"] = str(args.port)

    # Remove our custom args from sys.argv so that unittest doesn't get confused.
    sys.argv = [sys.argv[0]] + remaining_args

    # Discover and run all tests in the current folder.
    loader = unittest.TestLoader()
    tests = loader.discover(start_dir=os.path.dirname(__file__), pattern="test_*.py")
    testRunner = unittest.runner.TextTestRunner(verbosity=2)
    result = testRunner.run(tests)
    sys.exit(not result.wasSuccessful())

if __name__ == "__main__":
    main()
