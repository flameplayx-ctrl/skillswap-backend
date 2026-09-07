#!/bin/bash
# SkillSwap -> PythonAnywhere one-command setup (free, no card).
# Run this inside a PythonAnywhere Bash console AFTER creating a
# "manual configuration" web app (Python 3.10) in the Web tab.
set -e
USER_NAME=$(whoami)
REPO_DIR="$HOME/skillswap"
WSGI_FILE="/var/www/${USER_NAME}_pythonanywhere_com_wsgi.py"

echo "==> Cloning/updating code into $REPO_DIR"
if [ ! -d "$REPO_DIR/.git" ]; then
  git clone https://github.com/flameplayx-ctrl/skillswap-backend "$REPO_DIR"
else
  git -C "$REPO_DIR" pull --ff-only
fi

echo "==> Writing WSGI config -> $WSGI_FILE"
cat > "$WSGI_FILE" <<PYEOF
import sys
path = '/home/${USER_NAME}/skillswap'
if path not in sys.path:
    sys.path.insert(0, path)
from wsgi import application
PYEOF

echo ""
echo "✓ Code:     $REPO_DIR"
echo "✓ WSGI:     $WSGI_FILE"
echo ""
echo "NEXT STEP: open the PythonAnywhere 'Web' tab and click the green 'Reload' button."
echo "Your API will be live at: https://${USER_NAME}.pythonanywhere.com"
