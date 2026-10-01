# Contributing

Thank you for helping improve `check_opnsense`.

## Development setup

The plugin supports Python 3.9 or newer and has no third-party runtime
dependencies.

1. Fork and clone the repository.
2. Create a feature branch.
3. Make focused changes and add or update tests.
4. Run the test suite:

   ```bash
   python3 -m unittest discover -s tests -v
   python3 -m py_compile check_opnsense.py
   ```

5. If Director objects changed, rebuild the basket:

   ```bash
   python3 tools/build_director_basket.py
   ```

6. Open a pull request describing the OPNsense and Icinga Director versions
   used for testing.

Never commit API keys, API secrets, certificates or configuration exports
containing credentials.
