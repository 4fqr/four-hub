"""
Four-Hub · python/wrappers/__init__.py
Auto-imports all wrapper modules so the plugin system can discover them.
"""

from .nmap_wrapper        import NmapWrapper
from .nikto_wrapper       import NiktoWrapper
from .gobuster_wrapper    import GobusterWrapper
from .sqlmap_wrapper      import SqlmapWrapper
from .hydra_wrapper       import HydraWrapper
from .metasploit_wrapper  import MetasploitWrapper
from .ffuf_wrapper        import FfufWrapper
from .wpscan_wrapper      import WpscanWrapper
from .nuclei_wrapper      import NucleiWrapper
from .aircrack_wrapper    import AircrackWrapper
from .wifite_wrapper      import WifiteWrapper
from .john_wrapper        import JohnWrapper
from .hashcat_wrapper     import HashcatWrapper
from .dnsenum_wrapper     import DnsenumWrapper
from .theharvester_wrapper import TheHarvesterWrapper
from .eyewitness_wrapper  import EyewitnessWrapper
from .crackmapexec_wrapper import CrackmapexecWrapper
from .enum4linux_wrapper  import Enum4linuxWrapper
from .dirb_wrapper        import DirbWrapper
from .smbclient_wrapper   import SmbclientWrapper

__all__ = [
    "NmapWrapper", "NiktoWrapper", "GobusterWrapper", "SqlmapWrapper",
    "HydraWrapper", "MetasploitWrapper", "FfufWrapper", "WpscanWrapper",
    "NucleiWrapper", "AircrackWrapper", "WifiteWrapper", "JohnWrapper",
    "HashcatWrapper", "DnsenumWrapper", "TheHarvesterWrapper", "EyewitnessWrapper",
    "CrackmapexecWrapper", "Enum4linuxWrapper", "DirbWrapper", "SmbclientWrapper",
]


REGISTRY: dict = {w.name: w for w in __all__ if hasattr(w, 'name')}
