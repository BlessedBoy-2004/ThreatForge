import hashlib
import pefile
import yara
from typing import Dict, Any

class ThreatAnalyzer:
    """Advanced malware analysis engine"""
    
    def __init__(self, yara_rules: str = "rules/malware.yar"):
        self.rules = yara.compile(filepaths={'malware': yara_rules})
        
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Generate MD5, SHA1, SHA256 hashes"""
        with open(file_path, 'rb') as f:
            data = f.read()
            return {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()
            }
    
    def analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """Analyze Portable Executable files"""
        try:
            pe = pefile.PE(file_path)
            return {
                'sections': [{
                    'name': section.Name.decode().strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'size': section.SizeOfRawData
                } for section in pe.sections],
                'imports': [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
            }
        except pefile.PEFormatError:
            return {'error': 'Invalid PE file'}
    
    def match_yara(self, file_path: str) -> list:
        """Detect malware using YARA rules"""
        return [str(match) for match in self.rules.match(file_path)]

if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    hashes = analyzer.calculate_hashes("tests/test_samples/eicar.txt")
    print(f"🔍 File Hashes: {hashes}")
