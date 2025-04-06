# SSH Log Brute-Force Detector
This script analyzes an auth.log file to identify potential SSH brute-force attacks by counting failed login attempts per IP.

## Usage
\`\`\`bash
python ssh_log_analyzer.py <path_to_auth.log> [-t <threshold>]
\`\`\`
