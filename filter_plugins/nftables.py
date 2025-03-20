"""
Filter for generating nftables ruleset.
This helps to simplify nftable template.
"""
from typing import List, Set

from ansible.errors import AnsibleFilterError
from ansible.module_utils._text import to_native


def join_text(*args, separator=' '):
    """Join given text with separator, ignoring None and empty strings."""
    return separator.join(a for a in args if a)


class RuleChecker(object):
    RULE_KEYS = {'raw', 'match', 'action', 'description'}
    MATCH_KEYS = {
        'source', 'destination', 'protocol', 'ct_state', 'tcp_flags', 'meta',
        'ip_version',
    }
    # For deterministic match generation.
    MATCH_KEYS_LIST = sorted(MATCH_KEYS)
    ADDRESS_KEYS = {'address', 'port'}

    @staticmethod
    def check(rule):
        RuleChecker.check_keys(rule, RuleChecker.RULE_KEYS, 'rule')

        match = rule.get('match')
        if match:
            RuleChecker.check_match(match)

    @staticmethod
    def check_keys(dct, valid_keys, location):
        for k in dct.keys():
            if k not in valid_keys:
                raise AnsibleFilterError(f'invalid key in {location}: {k} {dct}')

    @staticmethod
    def check_match(match,):
        RuleChecker.check_keys(match, RuleChecker.MATCH_KEYS, 'match')

        source = match.get('source')
        if source:
            RuleChecker.check_keys(source, RuleChecker.ADDRESS_KEYS, 'match source')
        destination = match.get('destination')
        if destination:
            RuleChecker.check_keys(destination, RuleChecker.ADDRESS_KEYS, 'match destination')


class MatchGenerator(object):
    @staticmethod
    def gen_matches(match, valid_protocol: Set[str] = None) -> List[str]:
        """ Generates nftables matches expression.

        Because we can only specify a single protocol in a rule, we generate multiple matches if
        we have multiple protocols specified in rule.

        Refer to [Expressions](https://man.archlinux.org/man/nft.8#EXPRESSIONS) for valid matches.

        Args:
            match: match condition definition
            valid_protocol: used to check if protocol is valid

        Returns:
            match_expression: Each list item is a match expression. Empty list means no matches.
        """
        if not match:
            return []

        protocol = match.get('protocol', None)
        if protocol:
            protocol = protocol.split(',')
            if not RuleGenerator._check_protocol(protocol, valid_protocol):
                raise AnsibleFilterError(
                    f'invalid protocol in match, specified: {",".join(protocol)} allowed {",".join(valid_protocol)}')

        text = []
        for target in RuleChecker.MATCH_KEYS_LIST:
            if target == 'protocol':
                continue
            m = match.get(target)
            if not m:
                continue

            gen = getattr(MatchGenerator, f'match_{target}')
            if not gen:
                raise AnsibleFilterError('internal error while generating matches')
            text.append(gen(m))

        match_expr = ' '.join(text)
        if RuleGenerator._matches_port(match_expr) and not protocol:
            # When matches port without protocol, assume both tcp and udp.
            protocol = ['tcp', 'udp']

        if '{proto}' not in match_expr and protocol:
            # When we have tcp, udp, etc. matches, 'ip protcol' match is not needed.
            # Otherwise, we need to add ip protocol match.
            match_expr = ' '.join([match_expr, 'ip protocol {proto}'])

        if '{proto}' in match_expr:
            final_expr = []
            # Generate matches for each protocol.
            for p in protocol:
                final_expr.append(match_expr.format(proto=p))
            return final_expr
        else:
            return [match_expr]

    @staticmethod
    def match_source(source):
        saddr = source.get('address')
        saddr = f'ip saddr {saddr}' if saddr else None
        sport = source.get('port')
        # A place holder for multiple protocol expansion.
        sport = f'{{proto}} sport {sport}' if sport else None
        return join_text(saddr, sport)

    @staticmethod
    def match_destination(destination):
        daddr = destination.get('address')
        daddr = f'ip daddr {daddr}' if daddr else None
        dport = destination.get('port')
        # A place holder for multiple protocol expansion.
        dport = f'{{proto}} dport {dport}' if dport else None
        return join_text(daddr, dport)

    @staticmethod
    def match_ct_state(state):
        return f'ct state {state}'

    @staticmethod
    def match_tcp_flags(expression):
        return f'tcp flags {expression}'

    @staticmethod
    def match_meta(expression):
        return f'meta {expression}'

    @staticmethod
    def match_ip_version(version):
        return f'meta nfproto {version}'

    DYNAMIC_INTERFACE_PATTERN = ("ppp", "tun", "tap", "ipsec")

    @staticmethod
    def _is_dynamic_interface(itf_name):
        for pat in MatchGenerator.DYNAMIC_INTERFACE_PATTERN:
            if pat in itf_name:
                return True
        return False

    @staticmethod
    def match_output_interface(itf_name):
        """Generate output interface match.

        Args:
            itf_name: interface name

        Returns:
            str: match expressions

            If ``itf_name`` seems like dynamic interface (e.g. contains ppp, tap, tun), match with ``oifname``.
            Otherwise, match with ``oif`` for better performance.
        """
        if MatchGenerator._is_dynamic_interface(itf_name):
            return f'oifname "{itf_name}"'
        return f'oif {itf_name}'

    @staticmethod
    def match_input_interface(itf_name):
        """Generate input interface match.

        Refer to match_output_interface for more information.
        """
        for pat in ('ppp', 'tap', 'tun'):
            if pat in itf_name:
                return f'iifname "{itf_name}"'
        return f'iif {itf_name}'


class ActionGenerator(object):
    """This class serves as a namespace for all action expression generator.

    RuleGenerator.gen_actions uses getattr to find corresponding generation function.

    we only support NAT for IPv4 for now. (I don't see a strong need for IPv6 NAT for a home router.)
    """
    @staticmethod
    def gen_actions(action) -> str:
        """Generate nftables action.

        Multiple actions in a single rule is supported by nftables. Example:

            { tcp : jump tcp-chain, udp : jump udp-chain, icmp : jump icmp-chain }

        Let's leave this feature to raw rule.

        Returns:
            action: nftables action
        """
        if isinstance(action, str):
            action_method = getattr(ActionGenerator, f'action_{action}')
            return action_method()
        elif isinstance(action, dict):
            if len(action) > 1:
                raise AnsibleFilterError('only one action is supported')
            # Get the only item in action dict.
            name, action_def = next(iter(action.items()))
            action_method = getattr(ActionGenerator, f'action_{name}')
            if not action_method:
                raise AnsibleFilterError(f'invalid action in rule: {name}')
            return action_method(action_def)
        else:
            raise AnsibleFilterError(f'invalid action type {action.__class__}')

    @staticmethod
    def action_accept():
        return 'return'

    @staticmethod
    def action_accept_here():
        return 'accept'

    @staticmethod
    def action_drop():
        return 'drop'

    @staticmethod
    def action_source_nat(dct):
        address = dct.get('address')
        if not address:
            raise AnsibleFilterError('source NAT translation address not found')

        if address == 'masquerade':
            snat = 'masquerade'
        else:
            snat = f'snat ip to {address}'
            port = dct.get('port')
            if port:
                snat = f'{snat}:{port}'
        return snat

    @staticmethod
    def action_destination_nat(dct):
        address = dct.get('address')
        if not address:
            raise AnsibleFilterError('destination NAT translation address not found ')

        dnat = f'dnat ip to {address}'
        port = dct.get('port')
        if port:
            dnat = f'{dnat}:{port}'
        return dnat

    @staticmethod
    def action_tcp_option(dct):
        lst = [f'{k} set {v}' for k, v in dct.items()]
        return f'tcp option {" ".join(lst)}'


class RuleGenerator(object):
    @staticmethod
    def gen_statement(rule, add_counter: bool = True, indent=None):
        """Generate nftable statement.

        nftables rule structure:

            match1 [match2...] action1 [action2]

        Rule definition used in this class contains:
        - "match" (optional) to define match condition
          - supports source & destination address, port, protocol
        - "then" for action

        Args:
            add_counter: add counter before action if True
            indent: number of tables for indentation

        Returns:
            statement: that can be used in nftable script.
        """
        RuleChecker.check(rule)

        # print(rule)
        if indent is None:
            indent = ''
        else:
            indent = '\t' * indent

        # raw rule allows user to provide custom nftables rules.
        raw = rule.get('raw')
        if raw:
            return to_native(f'{indent}{raw}')

        match_def = rule.get('match')
        try:
            matches = MatchGenerator.gen_matches(match_def)
        except AnsibleFilterError:
            print(f'error in match:\n{rule}')
            raise

        action_def = rule.get('action')
        if not action_def:
            raise AnsibleFilterError(f'no action specified in rule\n{rule}')

        try:
            action = ActionGenerator.gen_actions(action_def)
        except AnsibleFilterError:
            print(f'error in action:\n{rule}')
            raise

        if add_counter:
            action = f'counter {action}'
        desc = rule.get('description')
        if desc:
            action = f'{action} comment "{desc}"'

        if matches:
            statement = []
            for m in matches:
                statement.append(f'{indent}{m} {action}')
            statement = '\n'.join(statement)
        else:
            statement = f'{indent}{action}'

        return to_native(statement)

    @staticmethod
    def open_dnat_port(rule, add_counter: bool = True, indent=None):
        rule = rule.copy()
        assert 'destination_nat' in rule['action']
        # Avoid further rule process for DNAT rules because it would fall to
        # default drop action.
        rule['action'] = 'accept_here'
        return RuleGenerator.gen_statement(rule, add_counter, indent)

    @staticmethod
    def _matches_port(expr):
        return ('sport' in expr) or ('dport' in expr)

    @staticmethod
    def _check_protocol(protocols, valid_protocol):
        if valid_protocol is None:
            return True
        for p in protocols:
            if p not in valid_protocol:
                return False
        return True


class FilterModule(object):
    def filters(self):
        return {
            'gen_nft_rule': RuleGenerator.gen_statement,
            'open_dnat_port': RuleGenerator.open_dnat_port,
            'input_itf': MatchGenerator.match_input_interface,
            'output_itf': MatchGenerator.match_output_interface,
        }
