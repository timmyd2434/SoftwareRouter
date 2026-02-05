#!/bin/bash
# Script to fix common unhandled error patterns in main.go

FILE="main.go"

# Fix: privKey, _ := runPrivilegedOutput -> privKey, err := runPrivilegedOutput with logging
sed -i 's/privKey, _ := runPrivilegedOutput(/privKey, err := runPrivilegedOutput(/g' "$FILE"
sed -i 's/pubKey, _ := runPrivilegedCombinedOutput(/pubKey, err := runPrivilegedCombinedOutput(/g' "$FILE"
sed -i 's/out, _ := runPrivilegedOutput(/out, err := runPrivilegedOutput(/g' "$FILE"

# Fix standalone runPrivileged calls - these need manual review but we'll log them
# sed -i 's/^\(\s*\)runPrivileged(/\1if err := runPrivileged(/g' "$FILE"

echo "Sed replacements complete. Manual fixes still needed for:"
echo "- runPrivileged() calls without error handling"
echo "- os.Remove() calls"
echo "- file.Close() calls"
