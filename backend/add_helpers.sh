#!/bin/bash
# Batch script to add helper functions for safe file closing

# Add safeClose helper to main.go if not exists
if ! grep -q "func safeClose" main.go; then
    # Add after writeJSON function
    sed -i '/^func generateSecureToken/i\
// safeClose safely closes a file and logs any errors\
func safeClose(f *os.File, context string) {\
\tif err := f.Close(); err != nil {\
\t\tlog.Printf("WARNING: Failed to close file (%s): %v", context, err)\
\t}\
}\
\
' main.go
fi

echo "Helper functions added"
