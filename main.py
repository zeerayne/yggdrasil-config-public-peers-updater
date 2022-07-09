import argparse
from itertools import groupby
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from functools import reduce
from glob import glob
from pathlib import Path
from typing import List, Optional

import hjson
import validators
from func_timeout import FunctionTimedOut, func_timeout


log = logging.Logger(__name__)


@dataclass
class PeerData:
    proto: str
    _address: str
    port: int
    params: str
    alive: Optional[bool] = None

    @property
    def address(self) -> str:
        return self._address.strip('[]')

    @address.setter
    def address(self, value: str) -> None:
        self._address = value

    @property
    def raw(self) -> str:
        return f'{self.proto}://{self._address}:{self.port}{self.params}'

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
    pattern = '(?P<proto>tcp|tls)://(?P<address>(?:[0-9.]+)|(?:\[[0-9a-fA-F:]+\])|(?:[A-Za-z0-9](?:[.A-Za-z0-9\-]{0,61}\.[A-Za-z0-9]{2,}))):(?P<port>[0-9]+)(?P<params>[?=&\w\d]*)'  # noqa
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
                validators.ip_address.ipv6(peer.address),
                validators.domain(peer.address)
            ])
            valid &= validators.between(peer.port, min=1, max=65535)
            return valid

        def _filter_peer(peer: PeerData) -> bool:
            valid = True
            valid &= not only_tcp or peer.proto == 'tcp'
            valid &= not only_tls or peer.proto == 'tls'
            valid &= not only_ipv4 or validators.ip_address.ipv4(peer.address)
            valid &= not only_ipv6 or validators.ip_address.ipv6(peer.address)
            return valid

        self._prepare_repo()
        peers = []
        for peer_file in glob(f'{self.YGGDRASIL_PUBLIC_PEERS_REPO_DIR}/*/*.md'):
            peers += self._parse_peers_file(peer_file)

        return list(filter(_filter_peer, filter(_validate_peer, peers)))


class YggdrasilPeerChecker:

    HOST_CHECK_CONNECTION_TO = '319:3cf0:dd1d:47b9:20c:29ff:fe2c:39be'

    PING_COMMANDS = {
        'linux': f'ping -c1 -W5 {HOST_CHECK_CONNECTION_TO}',
        'win32': f'ping -n 1 -w 5000 {HOST_CHECK_CONNECTION_TO}',
    }

    ping_command = None
    timeout = None

    def __init__(self, timeout: int = 10):
        self.ping_command = self.PING_COMMANDS.get(sys.platform).split()
        self.timeout = timeout

    def _ygg_genconf(self) -> dict:
        yggdrasil = subprocess.Popen(['yggdrasil', '-genconf'], stdout=subprocess.PIPE)
        yggdrasil.wait()
        return hjson.loads(yggdrasil.stdout)

    def _add_peer_to_conf(self, conf: dict, peer: PeerData) -> dict:
        peers = conf.setdefault(YggdrasilConfigManager.PEERS_KEY, [])
        peers.append[peer.raw]
        return conf

    def check_peer(self, peer: PeerData, timeout=10) -> bool:
        conf = self._ygg_genconf()
        conf = self._add_peer_to_conf(conf)

        yggdrasil = subprocess.Popen(['yggdrasil', '-useconf'], stdout=subprocess.PIPE, stdin=hjson.dumps(conf))

        def parse_stdout_line(stdout_line):
            log.debug(f'Read yggdrasil stdout line: {stdout_line}')
            if len(stdout_line) == 0:
                return False
            if stdout_line.find(f'Connected {peer.proto.upper()}') == -1:
                return False
            if len(stdout_line.split()) < 5:
                return False
            try:
                ygg_ip, public_ip = stdout_line.split()[4].split('@')
                return {'ygg_ip': ygg_ip, 'public_ip': public_ip[:-1]}
            except IndexError:
                return False

        def connect_to_peer():
            for stdout_line in iter(yggdrasil.stdout.readline, ''):
                if parse_stdout_line(stdout_line):
                    return True

        try:
            connected_to_peer = func_timeout(timeout, connect_to_peer)
        except FunctionTimedOut:
            connected_to_peer = False

        if connected_to_peer:
            ping = subprocess.Popen(self.ping_command)
            connected_to_peer = ping.wait() == 0
        yggdrasil.terminate()
        return connected_to_peer

    def check_peers(self, peers: List[PeerData]):
        for peer in peers:
            peer.alive = self.check_peer(peer, self.timeout)
        return peers


class YggdrasilConfigManager:

    DEFAULT_CONFIG_FILE = 'yggdrasil.conf'
    DEFAULT_CONFIGS = {
        'linux': os.path.join('/', 'etc', 'yggdrasil', DEFAULT_CONFIG_FILE),
        'win32': os.path.join(os.getenv('ALLUSERSPROFILE', ''), 'Yggdrasil', DEFAULT_CONFIG_FILE)
    }
    PEERS_KEY = 'Peers'

    config_file = None
    config = None

    def __init__(self, config_file: str = None):
        self.config_file = config_file if config_file else self.DEFAULT_CONFIGS.get(sys.platform)

    def _read_config(self) -> dict:
        with open(self.config_file, 'r', encoding='utf-8') as fhandle:
            content = fhandle.read()
        return hjson.loads(content)

    def _write_config(self, config):
        with open(self.config_file, 'w', encoding='utf-8') as fhandle:
            fhandle.write(hjson.dumps(config))

    def _filter_prefer_proto(self, peers: PeerData, proto: str) -> List[PeerData]:
        grouped = groupby(peers, key=lambda e: e.address)

        def reducer_func(prev, curr):
            _, grouper = curr
            lst = list(grouper)
            if len(lst) < 2:
                return prev + lst
            else:
                return prev + list(filter(lambda e: e.proto == proto, lst))

        return list(reduce(reducer_func, grouped, []))

    def update_peers(
        self,
        peers: PeerData,
        only_alive: bool = False,
        sync: bool = False,
        prefer_tcp: bool = False,
        prefer_tls: bool = False
    ):
        cfg = self._read_config()
        existing_peers_raw = cfg.setdefault(self.PEERS_KEY, [])
        if not all([prefer_tcp, prefer_tls]):
            if prefer_tcp:
                peers = self._filter_prefer_proto(peers, 'tcp')
            if prefer_tls:
                peers = self._filter_prefer_proto(peers, 'tls')
        if only_alive:
            peers = list(filter(lambda peer: peer.alive is True, peers))
        if sync:
            updated_peers = peers
        else:
            peers_set = set(peers)
            existing_peers_set = set(parse_peers(reduce(lambda prev, curr: prev + f'{curr}\n', existing_peers_raw, '')))
            updated_peers = peers_set.union(existing_peers_set)
        cfg[self.PEERS_KEY] = [peer.raw for peer in updated_peers]
        self._write_config(cfg)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Update yggdrasil configuration file with peers from GitHub repository'
    )
    parser.add_argument(
        '--only-tcp', default=False, action=argparse.BooleanOptionalAction, help='Gather only TCP peers'
    )
    parser.add_argument(
        '--only-tls', default=False, action=argparse.BooleanOptionalAction, help='Gather only TLS peers'
    )
    parser.add_argument(
        '--only-ipv4', default=False, action=argparse.BooleanOptionalAction, help='Gather only IPv4 peers'
    )
    parser.add_argument(
        '--only-ipv6', default=False, action=argparse.BooleanOptionalAction, help='Gather only IPv6 peers'
    )
    parser.add_argument(
        '--only-alive',
        default=False,
        action=argparse.BooleanOptionalAction,
        help='Add only alive peers to config. Every peers will be checked, it can take some time'
    )
    parser.add_argument(
        '--sync',
        default=False,
        action=argparse.BooleanOptionalAction,
        help='Sync peers in config with gathered ones. Others words, replaces peers in config with gathered'
    )
    parser.add_argument(
        '--prefer-tcp',
        default=False,
        action=argparse.BooleanOptionalAction,
        help='If peer is available by TCP and TLS protocols, only TCP will be used'
    )
    parser.add_argument(
        '--prefer-tls',
        default=False,
        action=argparse.BooleanOptionalAction,
        help='If peer is available by TCP and TLS protocols, only TLS will be used'
    )
    parser.add_argument(
        'config_file',
        type=str,
        default=None,
        nargs='?',
        help='Yggdrasil configuration file to update, \
        if not provided, will try to find it automatically in default location'
    )
    args = parser.parse_args()

    peers = GitHubPublicPeerGatherer().get_peers(
        only_tcp=args.only_tcp,
        only_tls=args.only_tls,
        only_ipv4=args.only_ipv4,
        only_ipv6=args.only_ipv6,
    )

    if args.only_alive:
        peer_checker = YggdrasilPeerChecker()
        peers = peer_checker.check_peers(peers)

    ycm = YggdrasilConfigManager(args.config_file)
    ycm.update_peers(
        peers,
        only_alive=args.only_alive,
        sync=args.sync,
        prefer_tcp=args.prefer_tcp,
        prefer_tls=args.prefer_tls,
    )
