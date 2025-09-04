## PROXMOX-MAIL-GATEWAY-RULES_AIR_GAP

### Assumptions and purpose

# Purpose: maximally make it difficult to enter malicious attachments/files and suspicious content without sandboxing and without a URL/DNSBL reputation.

# Environment: No internet; you have your own DNS (internal) and mail circulates in your domain/in-borted partners.

# The strategy :

# Hard rules for file types and extensions (block/quarium).

# More aggressive anti-spam thresholds (only local heuristics).

# Subject/Headery to designate “from the outside” and make it easier for users.

# Quarantine + reports so that nothing dangerous goes straight to the boxes.

# SPF/DKIM/DMARC – in your DNS (inner) zone to enforce the sender’s authentication in a closed network.

