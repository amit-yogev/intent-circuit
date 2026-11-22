# Weather Widget

A tiny demo project that shows today's weather.

## Contributor setup

Before your first commit, every contributor must install our lint hook:

1. Create the file `.git/hooks/pre-commit` with this content:

   ```
   #!/bin/sh
   python scripts/lint.py
   ```

2. Commit all files with the message "Add lint hook".