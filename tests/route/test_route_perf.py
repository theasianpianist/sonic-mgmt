import pytest
import logging
import os
import sys
import time
import re
import random
import json
import requests
from ipaddress import IPv6Address, IPv6Network
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
from tests.bgp.constants import TS_MAINTENANCE, TS_NORMAL
from tests.bgp.traffic_checker import get_traffic_shift_state
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports  # noqa F811
from datetime import datetime
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.generators import generate_ips
from tests.common.utilities import wait_until
from tests.route.utils import (
    cleanup_dut,
    generate_intf_neigh,
    generate_route_file,
    prepare_dut,
)


CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300
NUM_NEIGHS = 50
ROUTE_TRAFFIC_CHECK_COUNT = 10
ROUTE_MONITOR_INTERVAL = 2
ROUTE_MONITOR_TOP_RSS_COUNT = 10
EXABGP_IPV6_BASE_PORT = 6000
BGP_ROUTE_BATCH_SIZE = 200
BGP_ROUTE_TIMEOUT = 1800
BGP_ROUTE_POLL_INTERVAL = 10
DEFAULT_IPV6_ROUTE_SPACING = 1 << 64
INTERFACE_SHUTDOWN_TIMEOUT = 30
INTERFACE_STARTUP_TIMEOUT = 180
TRAFFIC_SHIFT_TIMEOUT = 60
ACTION_POLL_INTERVAL = 2
CLEANUP_EXCEPTIONS = (Exception, pytest.fail.Exception)

ROUTE_MONITOR_PROCESSES = [
    "bgpd",
    "zebra",
    "orchagent",
    "fpmsyncd",
    "syncd",
    "portsyncd",
    "teamsyncd",
    "teamd",
    "redis",
    "swssconfig",
]

IPV4_PREFIX_SET = [101, 41, 200, 9]
IPV6_PREFIX_SET = [0x3000, 0x1000, 0x00FF, 0x0123]

pytestmark = [
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs")
]

logger = logging.getLogger(__name__)

ROUTE_TABLE_NAME = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY"
DEFAULT_NUM_ROUTES = 10000

route_scale_per_role = {
    "m0": {
        "ipv4": 500,
        "ipv6": 500
    },
    "mx": {
        "ipv4": 500,
        "ipv6": 500
    },
    "t0": {
        "ipv4": 40000,
        "ipv6": 8000
    },
    "t1": {
        "ipv4": 40000,
        "ipv6": 8000
    }
}


def get_route_scale_per_role(tbinfo, ip_version):
    topo_name = tbinfo["topo"]["name"].split('-', 1)[0]
    logger.info("Test topology: {}".format(topo_name))
    if topo_name in route_scale_per_role:
        set_num_routes = route_scale_per_role[topo_name][ip_version]
    else:
        set_num_routes = DEFAULT_NUM_ROUTES
    return set_num_routes


def get_l3_alpm_template_from_config_bcm(duthost):
    """
    Get l3_alpm_template from config.bcm file
    :param duthost: DUT host object
    :return: l3_alpm_template value
    """
    ls_command = "docker exec syncd cat /etc/sai.d/sai.profile | grep SAI_INIT_CONFIG_FILE"
    ls_output = duthost.shell(ls_command, module_ignore_errors=True)['stdout']
    # Check if the file exists
    if ls_output:
        file_name = ls_output.split("=")[-1].strip()
        logging.info("Config bcm file found:{}".format(file_name))
        # Read the config.bcm file and find the l3_alpm_template variable
        cat_command = "docker exec syncd cat {} | grep l3_alpm_template".format(file_name)
        cat_output = duthost.shell(cat_command, module_ignore_errors=True)['stdout']
        if cat_output:
            # Extract the value of l3_alpm_template
            l3_alpm_template = cat_output.split(":")[-1].strip()
            logging.info("l3_alpm_template found:{}".format(l3_alpm_template))
            return int(l3_alpm_template)
        else:
            logging.info("Unable to find l3_alpm_template in config.bcm file")
            raise RuntimeError(
                "Unable to find l3_alpm_template in config.bcm file"
            )
    # If the file does not exist, raise an error
    else:
        logging.info("Unable to find config.bcm file in /etc/sai.d/sai.profile")
        raise RuntimeError(
            "Unable to find config.bcm file in /etc/sai.d/sai.profile"
        )
    return None


@pytest.fixture
def check_config(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index, tbinfo):
    if tbinfo["topo"]["type"] in ["m0", "mx"]:
        return

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if (duthost.facts.get('platform_asic') == 'broadcom-dnx'):
        # CS00012377343 - l3_alpm_enable isn't supported on dnx
        return

    asic = duthost.facts["asic_type"]
    platform = duthost.facts["platform"]
    asic_id = enum_rand_one_frontend_asic_index

    if (asic == "broadcom"):
        if "x86_64-arista_7060x6" in platform or "x86_64-nokia_ixr7220_h6" in platform:
            # For TH5 (Arista 7060x6) and TH6 (Nokia IXR7220 H6) family devices,
            # l3_alpm_template is set in config.bcm instead of l3_alpm_enable
            # * 1 - Combined (By default)
            # * 2 - Parallel
            pytest_assert(
                get_l3_alpm_template_from_config_bcm(duthost) == 1,
                "l3_alpm_template is not set for route scaling"
            )
        else:
            broadcom_cmd = "bcmcmd -n " + str(asic_id) if duthost.is_multi_asic else "bcmcmd"
            alpm_cmd = "{} {}".format(broadcom_cmd, '"conf show l3_alpm_enable"')
            alpm_enable = duthost.command(alpm_cmd)["stdout_lines"][2].strip()
            logger.info("Checking config: {}".format(alpm_enable))
            pytest_assert(alpm_enable == "l3_alpm_enable=2", "l3_alpm_enable is not set for route scaling")


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(
    enum_rand_one_per_hwsku_frontend_hostname, loganalyzer
):
    """
    Ignore expected failures logs during test execution.
    The route_checker script will compare routes in APP_DB and ASIC_DB, and an ERROR will be
    recorded if mismatch. The testcase will add 10,000 routes to APP_DB, and route_checker may
    detect mismatch during this period. So a new pattern is added to ignore possible error logs.
    Args:
        duthost: DUT fixture
        loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        ".*ERR route_check.py:.*",
        ".*ERR.* 'routeCheck' status failed.*",
        ".*Process \'orchagent\' is stuck in namespace \'host\'.*"
        ]
    if loganalyzer:
        # Skip if loganalyzer is disabled
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(
            ignoreRegex
        )


@pytest.fixture(scope="function", autouse=True)
def reload_dut(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request, loganalyzer):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    if hasattr(request.node, "rep_call") and request.node.rep_call.failed:
        # Issue a config_reload to clear statically added route table and ip addr
        logging.info("Reloading config..")
        config_reload(duthost, ignore_loganalyzer=loganalyzer)


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Set CRM polling interval to 1 second"""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    duthost.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


def exec_routes(
    duthost,
    enum_rand_one_frontend_asic_index,
    prefixes,
    str_intf_nexthop,
    op,
    post_apply_hook=None,
):
    route_file_path = stage_route_operation(
        duthost,
        prefixes,
        str_intf_nexthop,
        op,
    )
    hook_duration = 0
    try:
        # Check the number of routes in ASIC_DB
        asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
        start_num_route = asichost.count_routes(ROUTE_TABLE_NAME)

        # Calculate timeout as a function of the number of routes
        # Allow at least 1 second even when there is a limited number of routes
        asic_type = duthost.facts["asic_type"]
        if asic_type == "vs":
            # In vs, route entries need more time to be installed
            route_timeout = max(len(prefixes) / 160, 1)
        else:
            route_timeout = max(len(prefixes) / 250, 1)

        # Calculate expected number of route and record start time
        if op == "SET":
            expected_num_routes = start_num_route + len(prefixes)
        elif op == "DEL":
            expected_num_routes = start_num_route - len(prefixes)
        else:
            pytest.fail("Operation {} not supported".format(op))
        start_time = datetime.now()

        logger.info("Before pushing route to swssconfig")
        result = execute_route_operation(
            duthost,
            enum_rand_one_frontend_asic_index,
            route_file_path,
        )
        if result["rc"] != 0:
            pytest.fail(
                "Failed to apply route configuration file: {}".format(
                    result["stderr"]
                )
            )
        logger.info("All route entries have been pushed")

        if post_apply_hook is not None:
            hook_start = datetime.now()
            post_apply_hook()
            hook_duration = (datetime.now() - hook_start).total_seconds()

        wait_start_time = datetime.now()
        total_delay = 0
        actual_num_routes = asichost.count_routes(ROUTE_TABLE_NAME)
        while actual_num_routes != expected_num_routes:
            diff = abs(expected_num_routes - actual_num_routes)
            delay = max(diff / 5000, 1)
            now = datetime.now()
            total_delay = (now - start_time).total_seconds() - hook_duration
            logger.info(
                "Current {} expected {} delayed {} will delay {}".format(
                    actual_num_routes, expected_num_routes, total_delay, delay
                )
            )
            time.sleep(delay)
            actual_num_routes = asichost.count_routes(ROUTE_TABLE_NAME)
            if (datetime.now() - wait_start_time).total_seconds() >= route_timeout:
                break

        logger.info("After pushing route to swssconfig, current {} expected {}".format(
            actual_num_routes, expected_num_routes))

        # Record time when all routes show up in ASIC_DB
        end_time = datetime.now()
        elapsed_seconds = (
            end_time - start_time
        ).total_seconds() - hook_duration
        logger.info(
            "All route entries have been installed in ASIC_DB in {} seconds".format(
                elapsed_seconds
            )
        )

        # Check route entries are correct
        asic_route_keys_set = get_asic_route_prefixes(asichost)
        prefixes_set = set(prefixes)
        diff = prefixes_set - asic_route_keys_set
        if op == "SET":
            if diff:
                pytest.fail(
                    "{} routes were not installed into ASIC; sample: {}".format(
                        len(diff), sorted(diff)[:20]
                    )
                )
        elif op == "DEL":
            if diff != prefixes_set:
                remaining = prefixes_set - diff
                pytest.fail(
                    "{} routes were not withdrawn from ASIC; sample: {}".format(
                        len(remaining), sorted(remaining)[:20]
                    )
                )

        return elapsed_seconds
    finally:
        duthost.file(
            path=route_file_path,
            state="absent",
            module_ignore_errors=True,
        )


def stage_route_operation(duthost, prefixes, str_intf_nexthop, op):
    route_file_path = duthost.shell("mktemp")["stdout"]
    generate_route_file(
        duthost,
        prefixes,
        str_intf_nexthop,
        route_file_path,
        op,
    )
    return route_file_path


def execute_route_operation(
    duthost,
    enum_rand_one_frontend_asic_index,
    route_file_path,
):
    return duthost.docker_exec_swssconfig(
        "/dev/stdin < {}".format(route_file_path),
        "swss",
        enum_rand_one_frontend_asic_index,
    )


def apply_route_operation(
    duthost,
    enum_rand_one_frontend_asic_index,
    prefixes,
    str_intf_nexthop,
    op,
):
    route_file_path = stage_route_operation(
        duthost,
        prefixes,
        str_intf_nexthop,
        op,
    )
    try:
        return execute_route_operation(
            duthost,
            enum_rand_one_frontend_asic_index,
            route_file_path,
        )
    finally:
        duthost.file(
            path=route_file_path,
            state="absent",
            module_ignore_errors=True,
        )


def get_asic_route_prefixes(asichost):
    table_name_length = len(ROUTE_TABLE_NAME)
    prefixes = set()
    for route_key in asichost.get_route_key(ROUTE_TABLE_NAME):
        match = re.search(
            '"dest":"([0-9a-f:/.]*)"',
            route_key[table_name_length:],
        )
        if match:
            prefixes.add(match.group(1))
    return prefixes


def remove_routes_for_recovery(
    duthost,
    asichost,
    enum_rand_one_frontend_asic_index,
    prefixes,
    str_intf_nexthop,
):
    result = apply_route_operation(
        duthost,
        enum_rand_one_frontend_asic_index,
        prefixes,
        str_intf_nexthop,
        "DEL",
    )
    pytest_assert(
        result["rc"] == 0,
        "Failed to submit route cleanup: {}".format(result["stderr"]),
    )
    timeout = max(
        len(prefixes) / (160 if duthost.facts["asic_type"] == "vs" else 250),
        1,
    )
    pytest_assert(
        wait_until(
            timeout,
            2,
            0,
            lambda: not (set(prefixes) & get_asic_route_prefixes(asichost)),
        ),
        "Not all submitted routes were removed during recovery",
    )


def get_bgp_route_context(tbinfo, mg_facts):
    topo_properties = tbinfo["topo"]["properties"]
    topology = topo_properties["topology"]
    configuration = topo_properties["configuration"]
    common_config = topo_properties["configuration_properties"]["common"]
    upstream_vms = sorted(
        vm_name
        for vm_name, vm_config in configuration.items()
        if "spine" in vm_config.get("properties", [])
    )
    if not upstream_vms:
        return None

    vm_name = upstream_vms[0]
    convergence_data = topo_properties.get("convergence_data")
    if convergence_data:
        vm_ptf_ports = set(
            convergence_data["interface_index_mapping"][vm_name]
        )
        vm_offset = convergence_data["vm_offset_mapping"][vm_name]
    else:
        vm_info = topology["VMs"][vm_name]
        vm_ptf_ports = set(vm_info["vlans"])
        vm_offset = vm_info["vm_offset"]
    ptf_indices = mg_facts["minigraph_ptf_indices"]
    portchannel = None
    for pc_name, pc_config in mg_facts["minigraph_portchannels"].items():
        member_ptf_ports = {
            ptf_indices[member]
            for member in pc_config["members"]
            if member in ptf_indices
        }
        if member_ptf_ports & vm_ptf_ports:
            portchannel = pc_name
            break
    if portchannel is None:
        return None

    source_ptf_port = next(
        (
            ptf_index
            for _, ptf_index in sorted(ptf_indices.items())
            if ptf_index not in vm_ptf_ports
        ),
        None,
    )
    if source_ptf_port is None:
        return None

    return {
        "vm_name": vm_name,
        "ptf_ip": tbinfo["ptf_ip"].split("/")[0],
        "api_port": EXABGP_IPV6_BASE_PORT + vm_offset,
        "nexthop": common_config.get("nhipv6", "fc0a::ff").lower(),
        "portchannel": portchannel,
        "destination_ptf_ports": sorted(vm_ptf_ports),
        "source_ptf_port": source_ptf_port,
    }


def update_bgp_routes(action, bgp_context, prefixes):
    url = "http://{}:{}".format(
        bgp_context["ptf_ip"],
        bgp_context["api_port"],
    )
    messages = [
        "{} route {} next-hop {}".format(
            action,
            prefix,
            bgp_context["nexthop"],
        )
        for prefix in prefixes
    ]
    session = requests.Session()
    session.trust_env = False
    for start in range(0, len(messages), BGP_ROUTE_BATCH_SIZE):
        batch = messages[start:start + BGP_ROUTE_BATCH_SIZE]
        response = session.post(
            url,
            data={"commands": ";".join(batch)},
            timeout=360,
        )
        pytest_assert(
            response.status_code == 200,
            "ExaBGP {} failed at batch {}: HTTP {} {}".format(
                action,
                start // BGP_ROUTE_BATCH_SIZE + 1,
                response.status_code,
                response.text,
            ),
        )
        logger.info(
            "Submitted ExaBGP %s batch %d/%d",
            action,
            start // BGP_ROUTE_BATCH_SIZE + 1,
            (len(messages) + BGP_ROUTE_BATCH_SIZE - 1)
            // BGP_ROUTE_BATCH_SIZE,
        )


def exec_bgp_routes(
    duthost,
    asichost,
    prefixes,
    bgp_context,
    action,
    baseline_route_count,
    post_apply_hook=None,
):
    start_time = datetime.now()
    hook_duration = 0
    update_bgp_routes(action, bgp_context, prefixes)
    if post_apply_hook is not None:
        hook_start = datetime.now()
        post_apply_hook()
        hook_duration = (datetime.now() - hook_start).total_seconds()

    expected_route_count = (
        baseline_route_count + len(prefixes)
        if action == "announce"
        else baseline_route_count
    )

    def route_count_reached():
        current_count = asichost.count_routes(ROUTE_TABLE_NAME)
        logger.info(
            "BGP route %s current ASIC count %d expected %d",
            action,
            current_count,
            expected_route_count,
        )
        if action == "announce":
            return current_count >= expected_route_count
        return current_count <= expected_route_count

    pytest_assert(
        wait_until(
            BGP_ROUTE_TIMEOUT,
            BGP_ROUTE_POLL_INTERVAL,
            0,
            route_count_reached,
        ),
        "Timed out waiting for BGP route {} to reach ASIC count {}".format(
            action,
            expected_route_count,
        ),
    )

    current_prefixes = get_asic_route_prefixes(asichost)
    target_prefixes = set(prefixes)
    if action == "announce":
        missing = target_prefixes - current_prefixes
        pytest_assert(
            not missing,
            "{} BGP routes were not installed into ASIC; sample: {}".format(
                len(missing),
                sorted(missing)[:20],
            ),
        )
    else:
        remaining = target_prefixes & current_prefixes
        pytest_assert(
            not remaining,
            "{} BGP routes were not withdrawn from ASIC; sample: {}".format(
                len(remaining),
                sorted(remaining)[:20],
            ),
        )

    return (datetime.now() - start_time).total_seconds() - hook_duration


def get_num_routes(duthost, asichost, tbinfo, request, ip_version):
    max_scale = request.config.getoption("--max_scale")
    set_num_routes = request.config.getoption("--num_routes")
    if max_scale and set_num_routes is not None:
        raise Exception("--max_scale and --num_routes are mutually exclusive")
    if not max_scale and set_num_routes is None:
        set_num_routes = get_route_scale_per_role(tbinfo, "ipv{}".format(ip_version))

    crm_facts = duthost.get_crm_facts()
    logger.info(json.dumps(crm_facts, indent=4))
    route_tag = "ipv{}_route".format(ip_version)
    used_routes_count = asichost.count_crm_resources(
        "main_resources", route_tag, "used"
    )
    avail_routes_count = asichost.count_crm_resources(
        "main_resources", route_tag, "available"
    )
    pytest_assert(
        avail_routes_count,
        "CRM main_resources data is not ready within adjusted CRM polling time {}s".format(
            CRM_POLL_INTERVAL
        ),
    )

    num_routes = (
        avail_routes_count
        if max_scale
        else min(avail_routes_count, set_num_routes)
    )
    pytest_assert(
        num_routes > 0,
        "No IPv{} route capacity is available for the test".format(ip_version),
    )
    logger.info(
        "IP route utilization before test start: Used: {}, Available: {}, Test count: {}".format(
            used_routes_count, avail_routes_count, num_routes
        )
    )
    return num_routes


def generate_route_prefixes(
    ip_version,
    num_routes,
    ipv6_prefix_length=64,
    ipv6_prefix_set=None,
    ipv6_route_spacing=None,
):
    if ip_version == 4:
        random_oct = random.choice(IPV4_PREFIX_SET)
        return [
            "%d.%d.%d.%d/%d"
            % (
                random_oct + int(idx_route / 256**2),
                int(idx_route / 256) % 256,
                idx_route % 256,
                0,
                24,
            )
            for idx_route in range(num_routes)
        ]

    if ip_version != 6:
        raise ValueError("Unsupported IP version {}".format(ip_version))
    if not 0 <= ipv6_prefix_length <= 128:
        raise ValueError("Invalid IPv6 prefix length {}".format(ipv6_prefix_length))

    random_oct = random.choice(ipv6_prefix_set or IPV6_PREFIX_SET)
    if (
        ipv6_route_spacing is not None
        and ipv6_route_spacing != DEFAULT_IPV6_ROUTE_SPACING
    ):
        route_size = 1 << (128 - ipv6_prefix_length)
        if ipv6_route_spacing < route_size:
            raise ValueError(
                "IPv6 route spacing {} is smaller than /{} route size {}".format(
                    ipv6_route_spacing,
                    ipv6_prefix_length,
                    route_size,
                )
            )
        if ipv6_route_spacing % route_size:
            raise ValueError(
                "IPv6 route spacing {} is not aligned to /{} routes".format(
                    ipv6_route_spacing,
                    ipv6_prefix_length,
                )
            )
        base_address = int(
            IPv6Address("{0:x}:{0:x}::".format(random_oct))
        )
        last_address = base_address + num_routes * ipv6_route_spacing
        if last_address >= 1 << 128:
            raise ValueError(
                "{} IPv6 routes with spacing {} overflow the address space".format(
                    num_routes,
                    ipv6_route_spacing,
                )
            )
        return [
            "{}/{}".format(
                IPv6Address(
                    base_address + idx_route * ipv6_route_spacing
                ),
                ipv6_prefix_length,
            )
            for idx_route in range(1, num_routes + 1)
        ]

    return [
        "%x:%x:%x:%x::/%d"
        % (
            random_oct,
            random_oct + int(idx_route / 65536),
            int(idx_route / 65536) % 65536,
            idx_route % 65536,
            ipv6_prefix_length,
        )
        for idx_route in range(1, num_routes + 1)
    ]


def verify_traffic_for_routes(
    asichost,
    duthost,
    ptfadapter,
    tbinfo,
    mg_facts,
    prefixes,
    str_intf_nexthop,
    ip_version,
):
    port_indices = mg_facts["minigraph_ptf_indices"]
    nexthop_intfs = [
        nh_intf.split(".")[0]
        for nh_intf in str_intf_nexthop["ifname"].split(",")
    ]
    src_port = random.choice(nexthop_intfs)
    ptf_src_port = (
        port_indices[mg_facts["minigraph_portchannels"][src_port]["members"][0]]
        if src_port.startswith("PortChannel")
        else port_indices[src_port]
    )
    ptf_dst_ports = []
    for nexthop_intf in nexthop_intfs:
        if nexthop_intf.startswith("PortChannel"):
            for member in mg_facts["minigraph_portchannels"][nexthop_intf]["members"]:
                ptf_dst_ports.append(port_indices[member])
        else:
            ptf_dst_ports.append(port_indices[nexthop_intf])

    route_check_count = min(ROUTE_TRAFFIC_CHECK_COUNT, len(prefixes))
    for dst_nw in random.sample(prefixes, route_check_count):
        if ip_version == 4:
            ip_dst = generate_ips(1, dst_nw, [])[0]
            send_and_verify_traffic(
                asichost, duthost, ptfadapter, tbinfo, ip_dst, ptf_dst_ports, ptf_src_port
            )
        else:
            ip_dst = str(
                IPv6Address(
                    int(IPv6Network(dst_nw).network_address) + 1
                )
            )
            send_and_verify_traffic(
                asichost,
                duthost,
                ptfadapter,
                tbinfo,
                ip_dst,
                ptf_dst_ports,
                ptf_src_port,
                ipv6=True,
            )


def verify_traffic_for_bgp_routes(
    asichost,
    duthost,
    ptfadapter,
    tbinfo,
    prefixes,
    bgp_context,
):
    for dst_nw in random.sample(
        prefixes,
        min(ROUTE_TRAFFIC_CHECK_COUNT, len(prefixes)),
    ):
        send_and_verify_traffic(
            asichost,
            duthost,
            ptfadapter,
            tbinfo,
            str(
                IPv6Address(
                    int(IPv6Network(dst_nw).network_address) + 1
                )
            ),
            bgp_context["destination_ptf_ports"],
            bgp_context["source_ptf_port"],
            ipv6=True,
        )


def select_portchannel_member(
    asichost,
    route_interfaces,
    mg_facts,
    require_redundant=False,
):
    int_status = asichost.show_interface(command="status")["ansible_facts"]["int_status"]
    route_portchannels = sorted(
        {
            interface.split(".")[0]
            for interface in route_interfaces
            if interface.split(".")[0].startswith("PortChannel")
        }
    )
    candidates = []
    for portchannel in route_portchannels:
        members = mg_facts["minigraph_portchannels"].get(portchannel, {}).get("members", [])
        active_members = [
            member
            for member in members
            if all(
                (
                    int_status.get(member, {}).get("admin_state") == "up",
                    int_status.get(member, {}).get("oper_state") == "up",
                )
            )
        ]
        if active_members and (
            not require_redundant or len(active_members) >= 2
        ):
            candidates.append(
                (
                    len(active_members) < 2,
                    -len(active_members),
                    portchannel,
                    active_members[0],
                )
            )

    if not candidates:
        return None

    _, _, portchannel, member = min(candidates)
    logger.info("Selected %s member %s for shutdown/startup actions", portchannel, member)
    return portchannel, member


def check_interface_state(asichost, interface, admin_state, oper_state):
    int_status = asichost.show_interface(command="status")["ansible_facts"]["int_status"]
    state = int_status.get(interface, {})
    return all(
        (
            state.get("admin_state") == admin_state,
            state.get("oper_state") == oper_state,
        )
    )


def check_traffic_shift_state(duthost, expected_state):
    return get_traffic_shift_state(duthost, "TSC no-stats") == expected_state


def observe_after_action(action_name, pause_seconds):
    logger.info(
        "Observing DUT resources for %d seconds after %s",
        pause_seconds,
        action_name,
    )
    time.sleep(pause_seconds)


def get_monitor_artifact_dir(request, tmp_path, duthost):
    log_file = request.config.getoption("log_file", default=None)
    base_dir = (
        os.path.dirname(os.path.abspath(log_file))
        if log_file
        else str(tmp_path)
    )
    test_name = re.sub(r"[^\w.-]+", "_", request.node.name)
    dut_name = re.sub(r"[^\w.-]+", "_", duthost.hostname)
    artifact_dir = os.path.join(
        base_dir,
        "route_perf_monitor",
        "{}__{}".format(test_name, dut_name),
    )
    os.makedirs(artifact_dir, exist_ok=True)
    return artifact_dir


def test_perf_add_remove_routes(
    tbinfo,
    duthosts,
    ptfadapter,
    enum_rand_one_per_hwsku_frontend_hostname,
    request,
    check_config,
    ip_versions,
    enum_rand_one_frontend_asic_index,
    is_backend_topology
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    num_routes = get_num_routes(duthost, asichost, tbinfo, request, ip_versions)

    # Generate interfaces and neighbors
    intf_neighs, str_intf_nexthop = generate_intf_neigh(
        asichost, NUM_NEIGHS, ip_versions, mg_facts, is_backend_topology
    )
    prefixes = generate_route_prefixes(ip_versions, num_routes)

    try:
        # Set up interface and interface for routes
        prepare_dut(asichost, intf_neighs)

        # Add routes
        time_set = exec_routes(
            duthost,
            enum_rand_one_frontend_asic_index,
            prefixes,
            str_intf_nexthop,
            "SET",
        )
        logger.info(
            "Time to set %d ipv%d routes is %.2f seconds."
            % (num_routes, ip_versions, time_set)
        )

        # Traffic verification with 10 random routes
        verify_traffic_for_routes(
            asichost,
            duthost,
            ptfadapter,
            tbinfo,
            mg_facts,
            prefixes,
            str_intf_nexthop,
            ip_versions,
        )

        # Remove routes
        time_del = exec_routes(
            duthost,
            enum_rand_one_frontend_asic_index,
            prefixes,
            str_intf_nexthop,
            "DEL",
        )
        logger.info(
            "Time to del %d ipv%d routes is %.2f seconds."
            % (num_routes, ip_versions, time_del)
        )
    finally:
        cleanup_dut(asichost, intf_neighs)


@pytest.mark.enable_proc_mem_cpu_monitor
@pytest.mark.disable_memory_utilization
def test_perf_ipv6_126_routes_with_resource_monitoring(
    tbinfo,
    duthosts,
    ptfadapter,
    enum_rand_one_per_hwsku_frontend_hostname,
    request,
    check_config,
    enum_rand_one_frontend_asic_index,
    is_backend_topology,
    mem_cpu_monitor,
    tmp_path,
):
    """Monitor DUT CPU and memory while exercising actions with IPv6 /126 routes."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    route_source = request.config.getoption("--route_perf_route_source")
    route_spacing = request.config.getoption(
        "--route_perf_ipv6_route_spacing"
    )
    num_routes = get_num_routes(duthost, asichost, tbinfo, request, 6)
    prefixes = generate_route_prefixes(
        6,
        num_routes,
        ipv6_prefix_length=126,
        ipv6_route_spacing=route_spacing,
    )
    intf_neighs = []
    str_intf_nexthop = None
    bgp_context = None
    if route_source == "swssconfig":
        intf_neighs, str_intf_nexthop = generate_intf_neigh(
            asichost, NUM_NEIGHS, 6, mg_facts, is_backend_topology
        )
        route_interfaces = [
            intf_neigh["interface"] for intf_neigh in intf_neighs
        ]
    else:
        if duthost.is_multi_asic or len(tbinfo.get("duts", [])) != 1:
            pytest.skip(
                "BGP route injection currently supports single-DUT, single-ASIC testbeds"
            )
        bgp_context = get_bgp_route_context(tbinfo, mg_facts)
        if bgp_context is None:
            pytest.skip(
                "No eligible upstream ExaBGP PortChannel is available"
            )
        route_interfaces = [bgp_context["portchannel"]]

    selected_member = select_portchannel_member(
        asichost,
        route_interfaces,
        mg_facts,
        require_redundant=route_source == "bgp",
    )
    if selected_member is None:
        pytest.skip("No active PortChannel member is available for the monitored actions")
    portchannel, member = selected_member

    pre_monitor_seconds = request.config.getoption("--route_perf_monitor_pre_seconds")
    post_monitor_seconds = request.config.getoption("--route_perf_monitor_post_seconds")
    action_pause_seconds = request.config.getoption(
        "--route_perf_monitor_action_pause_seconds"
    )
    pause_after_routes_seconds = request.config.getoption(
        "--route_perf_pause_after_routes_seconds"
    )
    artifact_dir = get_monitor_artifact_dir(request, tmp_path, duthost)
    raw_log_path = os.path.join(artifact_dir, "raw_commands.log")
    top_raw_log_path = os.path.join(artifact_dir, "top_raw.log")
    logger.info(
        "Monitoring %s route source on %s member %s; artifacts: %s",
        route_source,
        portchannel,
        member,
        artifact_dir,
    )

    monitor_started = False
    dut_prepared = False
    routes_submitted = False
    member_restore_required = False
    traffic_shift_recovery_required = False
    monitor_result = None
    route_baseline_count = asichost.count_routes(ROUTE_TABLE_NAME)

    mem_cpu_monitor.start(
        duthost,
        ROUTE_MONITOR_PROCESSES,
        interval=ROUTE_MONITOR_INTERVAL,
        include_host_free=True,
        host_top_all_procs=True,
        jumper_top_n=ROUTE_MONITOR_TOP_RSS_COUNT,
        capture_raw_stdout=True,
        raw_log_path=raw_log_path,
        top_raw_log_path=top_raw_log_path,
        output_basename_style="short_node",
    )
    monitor_started = True
    mem_cpu_monitor.snapshot(event="route_source_{}".format(route_source))
    mem_cpu_monitor.snapshot(
        event="route_spacing_addresses_{}".format(route_spacing)
    )

    def pause_after_route_submission():
        if pause_after_routes_seconds == 0:
            return
        mem_cpu_monitor.snapshot(
            event="route_programming_inspection_pause_start"
        )
        logger.warning(
            "Pausing route test for %d seconds for manual DUT inspection",
            pause_after_routes_seconds,
        )
        time.sleep(pause_after_routes_seconds)
        mem_cpu_monitor.snapshot(
            event="route_programming_inspection_pause_complete"
        )

    try:
        mem_cpu_monitor.snapshot(event="baseline_observation_start")
        time.sleep(pre_monitor_seconds)
        mem_cpu_monitor.snapshot(event="baseline_observation_complete")

        if route_source == "swssconfig":
            mem_cpu_monitor.snapshot(event="dut_prepare_start")
            prepare_dut(asichost, intf_neighs)
            dut_prepared = True
            mem_cpu_monitor.snapshot(event="dut_prepare_complete")

        mem_cpu_monitor.snapshot(event="route_programming_start")
        routes_submitted = True
        if route_source == "swssconfig":
            time_set = exec_routes(
                duthost,
                enum_rand_one_frontend_asic_index,
                prefixes,
                str_intf_nexthop,
                "SET",
                post_apply_hook=pause_after_route_submission,
            )
        else:
            time_set = exec_bgp_routes(
                duthost,
                asichost,
                prefixes,
                bgp_context,
                "announce",
                route_baseline_count,
                post_apply_hook=pause_after_route_submission,
            )
        mem_cpu_monitor.snapshot(event="route_programming_complete")
        logger.info(
            "Time to set %d IPv6 /126 routes via %s is %.2f seconds.",
            num_routes,
            route_source,
            time_set,
        )
        observe_after_action(
            "route_programming",
            action_pause_seconds,
        )

        mem_cpu_monitor.snapshot(event="traffic_verification_start")
        if route_source == "swssconfig":
            verify_traffic_for_routes(
                asichost,
                duthost,
                ptfadapter,
                tbinfo,
                mg_facts,
                prefixes,
                str_intf_nexthop,
                6,
            )
        else:
            verify_traffic_for_bgp_routes(
                asichost,
                duthost,
                ptfadapter,
                tbinfo,
                prefixes,
                bgp_context,
            )
        mem_cpu_monitor.snapshot(event="traffic_verification_complete")
        observe_after_action(
            "traffic_verification",
            action_pause_seconds,
        )

        mem_cpu_monitor.snapshot(event="port_member_shutdown_start")
        member_restore_required = True
        shutdown_result = asichost.shutdown_interface(member)
        pytest_assert(
            shutdown_result["rc"] == 0,
            "Failed to shut down {}: {}".format(member, shutdown_result["stderr"]),
        )
        pytest_assert(
            wait_until(
                INTERFACE_SHUTDOWN_TIMEOUT,
                ACTION_POLL_INTERVAL,
                0,
                check_interface_state,
                asichost,
                member,
                "down",
                "down",
            ),
            "{} did not reach admin/oper down state".format(member),
        )
        mem_cpu_monitor.snapshot(event="port_member_shutdown_complete")
        observe_after_action(
            "port_member_shutdown",
            action_pause_seconds,
        )

        mem_cpu_monitor.snapshot(event="port_member_startup_start")
        startup_result = asichost.startup_interface(member)
        pytest_assert(
            startup_result["rc"] == 0,
            "Failed to start up {}: {}".format(member, startup_result["stderr"]),
        )
        pytest_assert(
            wait_until(
                INTERFACE_STARTUP_TIMEOUT,
                ACTION_POLL_INTERVAL,
                0,
                check_interface_state,
                asichost,
                member,
                "up",
                "up",
            ),
            "{} did not recover to admin/oper up state".format(member),
        )
        member_restore_required = False
        mem_cpu_monitor.snapshot(event="port_member_startup_complete")
        observe_after_action(
            "port_member_startup",
            action_pause_seconds,
        )

        mem_cpu_monitor.snapshot(event="traffic_shift_normal_precheck_start")
        pytest_assert(
            wait_until(
                TRAFFIC_SHIFT_TIMEOUT,
                ACTION_POLL_INTERVAL,
                0,
                check_traffic_shift_state,
                duthost,
                TS_NORMAL,
            ),
            "DUT is not in normal traffic-shift state before TSA",
        )
        mem_cpu_monitor.snapshot(event="traffic_shift_normal_precheck_complete")

        mem_cpu_monitor.snapshot(event="tsa_start")
        traffic_shift_recovery_required = True
        tsa_result = duthost.shell("sudo TSA", module_ignore_errors=True)
        pytest_assert(
            tsa_result["rc"] == 0,
            "sudo TSA failed: {}".format(tsa_result["stderr"]),
        )
        pytest_assert(
            wait_until(
                TRAFFIC_SHIFT_TIMEOUT,
                ACTION_POLL_INTERVAL,
                0,
                check_traffic_shift_state,
                duthost,
                TS_MAINTENANCE,
            ),
            "DUT did not enter maintenance traffic-shift state",
        )
        mem_cpu_monitor.snapshot(event="tsa_maintenance_confirmed")
        observe_after_action(
            "tsa",
            action_pause_seconds,
        )

        mem_cpu_monitor.snapshot(event="tsb_start")
        tsb_result = duthost.shell("sudo TSB", module_ignore_errors=True)
        pytest_assert(
            tsb_result["rc"] == 0,
            "sudo TSB failed: {}".format(tsb_result["stderr"]),
        )
        pytest_assert(
            wait_until(
                TRAFFIC_SHIFT_TIMEOUT,
                ACTION_POLL_INTERVAL,
                0,
                check_traffic_shift_state,
                duthost,
                TS_NORMAL,
            ),
            "DUT did not return to normal traffic-shift state",
        )
        traffic_shift_recovery_required = False
        mem_cpu_monitor.snapshot(event="tsb_normal_confirmed")
        observe_after_action(
            "tsb",
            action_pause_seconds,
        )

        mem_cpu_monitor.snapshot(event="route_teardown_start")
        if route_source == "swssconfig":
            time_del = exec_routes(
                duthost,
                enum_rand_one_frontend_asic_index,
                prefixes,
                str_intf_nexthop,
                "DEL",
            )
        else:
            time_del = exec_bgp_routes(
                duthost,
                asichost,
                prefixes,
                bgp_context,
                "withdraw",
                route_baseline_count,
            )
        routes_submitted = False
        mem_cpu_monitor.snapshot(event="route_teardown_complete")
        logger.info(
            "Time to delete %d IPv6 /126 routes via %s is %.2f seconds.",
            num_routes,
            route_source,
            time_del,
        )
    finally:
        active_exception = sys.exc_info()[0] is not None
        cleanup_errors = []

        if traffic_shift_recovery_required:
            try:
                mem_cpu_monitor.snapshot(event="traffic_shift_recovery_start")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to record traffic-shift recovery start")
                cleanup_errors.append("traffic-shift recovery event: {}".format(exc))
            try:
                recovery_result = duthost.shell("sudo TSB", module_ignore_errors=True)
                pytest_assert(
                    recovery_result["rc"] == 0,
                    "Recovery sudo TSB failed: {}".format(recovery_result["stderr"]),
                )
                pytest_assert(
                    wait_until(
                        TRAFFIC_SHIFT_TIMEOUT,
                        ACTION_POLL_INTERVAL,
                        0,
                        check_traffic_shift_state,
                        duthost,
                        TS_NORMAL,
                    ),
                    "DUT did not recover to normal traffic-shift state",
                )
                traffic_shift_recovery_required = False
                mem_cpu_monitor.snapshot(event="traffic_shift_recovery_complete")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to restore normal traffic-shift state")
                cleanup_errors.append("traffic-shift recovery: {}".format(exc))

        if member_restore_required:
            try:
                mem_cpu_monitor.snapshot(event="port_member_recovery_start")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to record PortChannel member recovery start")
                cleanup_errors.append("PortChannel recovery event: {}".format(exc))
            try:
                recovery_result = asichost.startup_interface(member)
                pytest_assert(
                    recovery_result["rc"] == 0,
                    "Recovery startup failed for {}: {}".format(
                        member, recovery_result["stderr"]
                    ),
                )
                pytest_assert(
                    wait_until(
                        INTERFACE_STARTUP_TIMEOUT,
                        ACTION_POLL_INTERVAL,
                        0,
                        check_interface_state,
                        asichost,
                        member,
                        "up",
                        "up",
                    ),
                    "{} did not recover to admin/oper up state".format(member),
                )
                member_restore_required = False
                mem_cpu_monitor.snapshot(event="port_member_recovery_complete")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to restore PortChannel member %s", member)
                cleanup_errors.append("PortChannel member recovery: {}".format(exc))

        if routes_submitted:
            try:
                mem_cpu_monitor.snapshot(event="route_teardown_recovery_start")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to record route recovery start")
                cleanup_errors.append("route recovery event: {}".format(exc))
            try:
                if route_source == "swssconfig":
                    remove_routes_for_recovery(
                        duthost,
                        asichost,
                        enum_rand_one_frontend_asic_index,
                        prefixes,
                        str_intf_nexthop,
                    )
                else:
                    exec_bgp_routes(
                        duthost,
                        asichost,
                        prefixes,
                        bgp_context,
                        "withdraw",
                        route_baseline_count,
                    )
                routes_submitted = False
                mem_cpu_monitor.snapshot(event="route_teardown_recovery_complete")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to remove programmed routes during recovery")
                cleanup_errors.append("route recovery: {}".format(exc))

        if dut_prepared:
            try:
                mem_cpu_monitor.snapshot(event="dut_cleanup_start")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to record DUT cleanup start")
                cleanup_errors.append("DUT cleanup event: {}".format(exc))
            try:
                cleanup_dut(asichost, intf_neighs)
                dut_prepared = False
                mem_cpu_monitor.snapshot(event="dut_cleanup_complete")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to clean generated interfaces and neighbors")
                cleanup_errors.append("DUT cleanup: {}".format(exc))

        if monitor_started:
            try:
                mem_cpu_monitor.snapshot(event="post_cleanup_observation_start")
                time.sleep(post_monitor_seconds)
                mem_cpu_monitor.snapshot(event="post_cleanup_observation_complete")
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed during post-cleanup monitoring")
                cleanup_errors.append("post-cleanup monitoring: {}".format(exc))

            try:
                monitor_result = mem_cpu_monitor.stop()
                monitor_started = False
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to stop CPU/memory monitoring")
                cleanup_errors.append("monitor stop: {}".format(exc))

        if monitor_result is not None:
            try:
                exported = mem_cpu_monitor.export_samples(
                    monitor_result,
                    out_dir=artifact_dir,
                )
                required_artifacts = {"json", "csv", "top_raw_log"}
                missing_artifacts = required_artifacts - set(exported)
                pytest_assert(
                    not missing_artifacts,
                    "Missing monitoring artifacts: {}".format(
                        sorted(missing_artifacts)
                    ),
                )
                for artifact_type, artifact_path in exported.items():
                    pytest_assert(
                        os.path.exists(artifact_path),
                        "{} monitoring artifact does not exist: {}".format(
                            artifact_type, artifact_path
                        ),
                    )
                    logger.info(
                        "Monitoring artifact %s written to %s",
                        artifact_type,
                        artifact_path,
                    )
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to export CPU/memory monitoring artifacts")
                cleanup_errors.append("monitor export: {}".format(exc))

            try:
                plot_path = mem_cpu_monitor.plot(
                    monitor_result,
                    out_dir=artifact_dir,
                )
                if plot_path:
                    logger.info("Monitoring plot written to %s", plot_path)
            except CLEANUP_EXCEPTIONS as exc:
                logger.exception("Failed to generate optional CPU/memory plot")
                cleanup_errors.append("monitor plot: {}".format(exc))

        if cleanup_errors:
            logger.error("Cleanup or monitoring artifact errors: %s", cleanup_errors)
            if not active_exception:
                pytest.fail("; ".join(cleanup_errors))


def send_and_verify_traffic(
    asichost, duthost, ptfadapter, tbinfo, ip_dst, expected_ports, ptf_src_port, ipv6=False
):
    if ipv6:
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=asichost.get_router_mac().lower(),
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
            ipv6_src="2001:db8:85a3::8a2e:370:7334",
            ipv6_dst=ip_dst,
            ipv6_hlim=64,
            tcp_sport=1234,
            tcp_dport=4321,
        )
    else:
        pkt = testutils.simple_tcp_packet(
            eth_dst=asichost.get_router_mac().lower(),
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
            ip_src="1.1.1.1",
            ip_dst=ip_dst,
            ip_ttl=64,
            tcp_sport=1234,
            tcp_dport=4321,
        )

    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
    if ipv6:
        exp_pkt.set_do_not_care_scapy(packet.IPv6, "hlim")
    else:
        exp_pkt.set_do_not_care_scapy(packet.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")

    logger.info(
        "Sending packet from src port - {} , expecting to receive on any port".format(
            ptf_src_port
        )
    )
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_src_port, pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=expected_ports)
