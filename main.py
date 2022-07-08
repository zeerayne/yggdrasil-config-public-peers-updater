import logging
import os
import re
import subprocess
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import List, Optional

import validators
log = logging.Logger(__name__)


@dataclass
class PeerData:
    proto: str
    address: str
    port: int
    params: str
    alive: Optional[bool] = None

    @property
    def raw(self) -> str:
        return f'{self.proto}://{self.address}:{self.port}{self.params}'

    def __hash__(self) -> int:
        return hash(self.raw)


class cd:
    """
    Sets the cwd within the context
    Args:
        path (Path): The path to the cwd
    """

    def __init__(self, path: Path):
        self.path = path
        self.origin = Path().absolute()

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_value, tb):
        os.chdir(self.origin)


def parse_peers(text: str, regex_string_suffux: str = '') -> List[PeerData]:
    pattern = '(?P<proto>tcp|tls)://(?P<address>(?:[0-9.]+)|(?:\[[0-9a-fA-F:]+\])|(?:[A-Za-z0-9](?:[.A-Za-z0-9\-]{0,61}\.[A-Za-z0-9]{2,}))):(?P<port>[0-9]+)(?P<params>[?=&\w\d]*)'
    pattern += regex_string_suffux
    address_matches = re.finditer(pattern, text)
    return [
        PeerData(m.group('proto'),
                 m.group('address'), int(m.group('port')), m.group('params'))
        for m in address_matches
    ]


class GitHubPublicPeerGatherer:
    YGGDRASIL_PUBLIC_PEERS_REPO_DIR = 'public-peers'
    YGGDRASIL_PUBLIC_PEERS_REPO_URL = 'https://github.com/yggdrasil-network/public-peers.git'

    def _execute_shell_command(self, command) -> int:
        proc = subprocess.Popen(command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, shell=True)
        proc.wait()
        return proc.returncode

    def _prepare_repo(self):
        if os.path.exists(self.YGGDRASIL_PUBLIC_PEERS_REPO_DIR):
            with cd(Path(self.YGGDRASIL_PUBLIC_PEERS_REPO_DIR)):
                exit_code = self._execute_shell_command('git pull')
        else:
            cmd = f'git clone {self.YGGDRASIL_PUBLIC_PEERS_REPO_URL} {self.YGGDRASIL_PUBLIC_PEERS_REPO_DIR}'
            exit_code = self._execute_shell_command(cmd)
        return exit_code == 0

    def _parse_peers_file(self, file_path) -> PeerData:
        with open(file_path, encoding='utf-8') as fhandle:
            filecontent = fhandle.read()
        return parse_peers(filecontent, r'`')

    def get_peers(
        self,
        only_tcp: bool = False,
        only_tls: bool = False,
        only_ipv4: bool = False,
        only_ipv6: bool = False
    ) -> List[PeerData]:

        def _validate_peer(peer: PeerData) -> bool:
            valid = True
            valid &= any([
                validators.ip_address.ipv4(peer.address),
                validators.ip_address.ipv6(peer.address.strip('[]')),
                validators.domain(peer.address)
            ])
            valid &= validators.between(peer.port, min=1, max=65535)
            return valid

        def _filter_peer(peer: PeerData) -> bool:
            valid = True
            valid &= not only_tcp or peer.proto == 'tcp'
            valid &= not only_tls or peer.proto == 'tls'
            valid &= not only_ipv4 or validators.ip_address.ipv4(peer.address)
            valid &= not only_ipv6 or validators.ip_address.ipv6(peer.address.strip('[]'))
            return valid

        self._prepare_repo()
        peers = []
        for peer_file in glob(f'{self.YGGDRASIL_PUBLIC_PEERS_REPO_DIR}/*/*.md'):
            peers += self._parse_peers_file(peer_file)

        return list(filter(_filter_peer, filter(_validate_peer, peers)))

