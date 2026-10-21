# Security headers, included in every location that sets its own add_header
# (nginx drops inherited add_header lines once a location declares any).
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header X-Frame-Options "DENY" always;
