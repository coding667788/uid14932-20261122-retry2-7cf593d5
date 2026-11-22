"""multicast_guard: offline dual multicast-tree planning and audit tool.

All inputs are synthetic.  Only two encapsulation labels are simulated:

* ``"C"`` -- ciphertext encapsulation;
* ``"P"`` -- plaintext encapsulation.

No real network, key material or cryptography is involved.
"""

__version__ = "1.0.0"

LABEL_CIPHER = "C"
LABEL_PLAIN = "P"
LABELS = (LABEL_CIPHER, LABEL_PLAIN)

# Published capacity bounds of the synthetic input format.
MAX_NODES = 18
MAX_EDGES = 32
MAX_RECEIVERS = 7
MAX_FAULT_DOMAINS = 6
