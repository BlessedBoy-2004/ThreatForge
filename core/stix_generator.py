from stix2 import Indicator, Bundle
from mitreattack.stix20 import MitreAttackData
from datetime import datetime

class STIXGenerator:
    """Generate STIX 2.1 threat intelligence"""
    
    def __init__(self):
        self.mitre = MitreAttackData("enterprise-attack.json")
        
    def create_indicator(self, hash_md5: str, technique_id: str) -> Bundle:
        """Create STIX indicator with MITRE mapping"""
        technique = self.mitre.get_technique(technique_id)
        return Bundle(objects=[
            Indicator(
                name=f"Malware IOC: {hash_md5}",
                pattern=f"[file:hashes.md5 = '{hash_md5}']",
                pattern_type="stix",
                valid_from=datetime.now(),
                kill_chain_phases=[{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": technique.name
                }]
            )
        ])

if __name__ == "__main__":
    generator = STIXGenerator()
    stix_bundle = generator.create_indicator("44d88612fea8a8f36de82e1278abb02f", "T1190")
    print("🎯 STIX Bundle Created:", stix_bundle.serialize(pretty=True))
