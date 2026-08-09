# RansomEye workspace rules

## Project root

Always treat the opened workspace root as the project root.
Never hardcode machine-specific paths such as D:\n\Project\RansomEye.

## Python

Use the workspace virtual environment:

.\.venv\Scripts\python.exe

Run Python tools through:

.\.venv\Scripts\python.exe -m <tool>

Do not use the global Python installation when the virtual environment exists.

## Testing

Run the focused test first, then the complete suite:

.\.venv\Scripts\python.exe -m pytest -q tests\<focused_test>.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp="$PWD\.pytest-tmp"

Do not commit .pytest-tmp, .pytest-temp, generated reports, database backups, or temporary databases.

## Database safety

Never modify data\ransomeye.db during tests.
Use a temporary database or disposable copy first.

## Git safety

Do not reset, delete, or rewrite existing work without explicit approval.
Review git diff --check before committing.
Run tests before committing.
