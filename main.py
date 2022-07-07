import http.client
import json
import logging
import os
import re
import select
import subprocess
import time
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import List

import validators


@dataclass
class PeerData:
    proto: str
    address: str
    port: int
    params: str
    raw: str


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


class GitHubPublicPeerGatherer:
    YGGDRASIL_PUBLIC_PEERS_REPO_DIR = 'public-peers'
    YGGDRASIL_PUBLIC_PEERS_REPO_URL = 'https://github.com/yggdrasil-network/public-peers.git'

    # filter params
    only_tcp = None
    only_tls = None
    only_ipv4 = None
    only_ipv6 = None
    prefer_tcp = None
    prefer_tls = None

    def __init__(
        self,
        only_tcp: bool = False,
        only_tls: bool = False,
        only_ipv4: bool = False,
        only_ipv6: bool = False,
        prefer_tcp: bool = False,
        prefer_tls: bool = False,
    ) -> None:
        self.only_tcp = only_tcp
        self.only_tls = only_tls
        self.only_ipv4 = only_ipv4
        self.only_ipv6 = only_ipv6
        self.prefer_tcp = prefer_tcp
        self.prefer_tls = prefer_tls

    def _execute_shell_command(command) -> int:
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

    def _parse_peers(self, text) -> PeerData:
        address_matches = re.finditer(
            r'(?P<proto>tcp|tls)://\
            (?P<address>(?:[0-9.]+)|(?:\[[0-9a-fA-F:]+\])|(?:[A-Za-z0-9](?:[.A-Za-z0-9\-]{0,61}\.[A-Za-z0-9]{2,}))):\
            (?P<port>[0-9]+)(?P<params>[?=\w\d]*)\`', text
        )
        return [
            PeerData(
                m.group('proto'),
                m.group('address').strip('[]'), int(m.group('port')), m.group('params'), m.string
            ) for m in address_matches
        ]

    def _parse_peers_file(self, file_path) -> PeerData:
        with open(file_path) as fhandle:
            filecontent = fhandle.read()
        return self._parse_peers(filecontent)

    def get_peers(self) -> List[PeerData]:
        def _validate_peer(peer: PeerData) -> bool:
            valid = True
            valid &= any(
                validators.ip_address.ipv4(peer.address), validators.ip_address.ipv6(peer.address),
                validators.domain(peer.address)
            )
            valid &= validators.between(peer.port, min=1, max=65535)
            return valid

        def _filter_peer(peer: PeerData) -> bool:
            valid = True
            valid &= not self.only_tcp or peer.proto == 'tcp'
            valid &= not self.only_tls or peer.proto == 'tls'
            valid &= not self.only_ipv4 or validators.ip_address.ipv4(peer.address)
            valid &= not self.only_ipv6 or validators.ip_address.ipv6(peer.address)
            return valid
            
        self._prepare_repo()
        peers = []
        for peer_file in glob(f'{self.YGGDRASIL_PUBLIC_PEERS_REPO_DIR}/*/*.md'):
            peers += self._parse_peers_file(peer_file)
        
        return list(filter(_filter_peer, filter(_validate_peer, peers)))
