from __future__ import annotations
import whois
import json
import csv
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import logging
from dataclasses import dataclass, asdict
from colorama import Fore, Style, init
import asyncio
import concurrent.futures
from functools import lru_cache
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
init(strip=False, autoreset=True)

@dataclass
class WhoisResult:
    domain: str
    registrar: Optional[str] = None
    whois_server: Optional[str] = None
    creation_date: Optional[Union[datetime, List[datetime]]] = None
    expiration_date: Optional[Union[datetime, List[datetime]]] = None
    updated_date: Optional[Union[datetime, List[datetime]]] = None
    status: Optional[Union[str, List[str]]] = None
    name_servers: Optional[Union[str, List[str]]] = None
    emails: Optional[Union[str, List[str]]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: str(v) if v is not None else None for k, v in asdict(self).items()}

class WhoisTool:
    def __init__(self):
        self.results: List[WhoisResult] = []
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

    async def perform_whois_async(self, domain: str) -> Optional[WhoisResult]:
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                self._executor,
                self._perform_whois_sync,
                domain
            )
            return result
        except Exception as e:
            logger.error(f"Error during WHOIS lookup for {domain}: {e}")
            return None

    @lru_cache(maxsize=128)
    def _perform_whois_sync(self, domain: str) -> Optional[WhoisResult]:
        try:
            logger.info(f"Performing WHOIS lookup for: {domain}")
            data = whois.whois(domain)
            
            result = WhoisResult(
                domain=domain,
                registrar=data.registrar,
                whois_server=data.whois_server,
                creation_date=data.creation_date,
                expiration_date=data.expiration_date,
                updated_date=data.updated_date,
                status=data.status,
                name_servers=data.name_servers,
                emails=data.emails
            )
            
            self.results.append(result)
            logger.info(f"WHOIS lookup successful for {domain}")
            return result
        except Exception as e:
            logger.error(f"Error during WHOIS lookup for {domain}: {e}")
            return None

    def display_result(self, result: Optional[WhoisResult]) -> None:
        if not result:
            print(Fore.RED + "[!] No results available.")
            return

        print(Fore.CYAN + """\n
╔═══════════════╗
║ WHOIS Results ║
╚═══════════════╝""")
        for key, value in result.to_dict().items():
            if value:
                print(f"{Fore.LIGHTBLUE_EX}{key:<20}: {Fore.LIGHTWHITE_EX}{value}")

    def export_to_json(self, filename: Union[str, Path]) -> None:
        filepath = Path(filename)
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with filepath.open('w', encoding='utf-8') as f:
                json.dump(
                    [r.to_dict() for r in self.results],
                    f,
                    indent=4,
                    ensure_ascii=False
                )
            logger.info(f"Results exported to JSON: {filepath}")
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            raise

    def export_to_csv(self, filename: Union[str, Path]) -> None:
        filepath = Path(filename)
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with filepath.open('w', newline='', encoding='utf-8') as f:
                if not self.results:
                    raise ValueError("No results to export")
                    
                writer = csv.DictWriter(f, fieldnames=self.results[0].to_dict().keys())
                writer.writeheader()
                writer.writerows(r.to_dict() for r in self.results)
            logger.info(f"Results exported to CSV: {filepath}")
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            raise

async def main():
    tool = WhoisTool()
    
    while True:
        try:
            print(Fore.LIGHTRED_EX + f"""
██╗    ██╗██╗  ██╗ ██████╗ ██╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗
██║    ██║██║  ██║██╔═══██╗██║██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
██║ █╗ ██║███████║██║   ██║██║███████╗       ██║   ██║   ██║██║   ██║██║     ███████╗
██║███╗██║██╔══██║██║   ██║██║╚════██║       ██║   ██║   ██║██║   ██║██║     ╚════██║
╚███╔███╔╝██║  ██║╚██████╔╝██║███████║       ██║   ╚██████╔╝╚██████╔╝███████╗███████║
 ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝{Fore.CYAN}
╔══════════════╗
║ OPTIONS MENU ║
╚══════════════╝{Fore.LIGHTBLUE_EX}
╔═════════════════════════╗
║ 1. Perform WHOIS Lookup ║
║ 2. Export to JSON       ║
║ 3. Export to CSV        ║
║ 4. Quit                 ║
╚═════════════════════════╝
""")
            choice = input(Fore.LIGHTCYAN_EX + "Choose an option: ").strip()

            if choice == "1":
                domain = input(Fore.LIGHTCYAN_EX + "Enter domain name (e.g., example.com): ").strip()
                result = await tool.perform_whois_async(domain)
                tool.display_result(result)
            elif choice == "2":
                filename = input(Fore.LIGHTCYAN_EX + "Enter JSON filename (e.g., results.json): ").strip()
                tool.export_to_json(filename)
            elif choice == "3":
                filename = input(Fore.LIGHTCYAN_EX + "Enter CSV filename (e.g., results.csv): ").strip()
                tool.export_to_csv(filename)
            elif choice == "4":
                print(Fore.CYAN + "Thank you for using WHOIS Tool. Goodbye!")
                break
            else:
                print(Fore.RED + "Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nOperation cancelled by user.")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())
